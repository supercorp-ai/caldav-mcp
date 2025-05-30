#!/usr/bin/env node

import { hideBin } from 'yargs/helpers'
import yargs from 'yargs'
import express, { Request, Response as ExpressResponse } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { OAuth2Client } from 'google-auth-library'
import { DAVClient, DAVNamespace, DAVDepth } from 'tsdav'
import { Redis } from '@upstash/redis'

// --------------------------------------------------------------------
// Helper: JSON Response Formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(data, null, 2)
      }
    ]
  };
}

// --------------------------------------------------------------------
// Configuration & Storage Interface
// --------------------------------------------------------------------
interface Config {
  port: number;
  transport: 'sse' | 'stdio';
  storage: 'memory-single' | 'memory' | 'upstash-redis-rest';
  googleClientId: string;
  googleClientSecret: string;
  googleRedirectUri: string;
  googleState?: string;
  storageHeaderKey?: string;
  upstashRedisRestUrl?: string;
  upstashRedisRestToken?: string;
}

interface Storage {
  get(memoryKey: string): Promise<Record<string, any> | undefined>;
  set(memoryKey: string, data: Record<string, any>): Promise<void>;
}

// --------------------------------------------------------------------
// In-Memory Storage Implementation
// --------------------------------------------------------------------
class MemoryStorage implements Storage {
  private storage: Record<string, Record<string, any>> = {};
  async get(memoryKey: string) {
    return this.storage[memoryKey];
  }
  async set(memoryKey: string, data: Record<string, any>) {
    // Merge new data with existing data so that previously stored credentials are preserved.
    this.storage[memoryKey] = { ...this.storage[memoryKey], ...data };
  }
}

// --------------------------------------------------------------------
// Upstash Redis Storage Implementation
// --------------------------------------------------------------------
class RedisStorage implements Storage {
  private redis: Redis;
  private keyPrefix: string;
  constructor(redisUrl: string, redisToken: string, keyPrefix: string) {
    this.redis = new Redis({ url: redisUrl, token: redisToken });
    this.keyPrefix = keyPrefix;
  }
  async get(memoryKey: string): Promise<Record<string, any> | undefined> {
    const data = await this.redis.get<Record<string, any>>(`${this.keyPrefix}:${memoryKey}`);
    return data === null ? undefined : data;
  }
  async set(memoryKey: string, data: Record<string, any>) {
    const existing = (await this.get(memoryKey)) || {};
    const newData = { ...existing, ...data };
    await this.redis.set(`${this.keyPrefix}:${memoryKey}`, JSON.stringify(newData));
  }
}

// --------------------------------------------------------------------
// CalDAV OAuth & DAV Client Helpers
// --------------------------------------------------------------------
/**
 * For Google CalDAV, we use OAuth2.
 * For Apple CalDAV, we use Basic authentication.
 * Stored credentials (per memoryKey) will include:
 *   For Google: { provider: "google", account: string, refreshToken: string }
 *   For Apple: { provider: "apple", account: string, password: string }
 */

// Google CalDAV Authentication
async function authGoogle(
  args: { account: string; code: string },
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<{ success: boolean; provider: string; account: string }> {
  const client = new OAuth2Client(config.googleClientId, config.googleClientSecret, config.googleRedirectUri);
  const { tokens } = await client.getToken(args.code.trim());
  if (!tokens.refresh_token) {
    throw new Error('No refresh token returned by Google.');
  }
  client.setCredentials(tokens);
  await storage.set(memoryKey, { provider: 'google', account: args.account, refreshToken: tokens.refresh_token });
  return { success: true, provider: 'google', account: args.account };
}

// Apple CalDAV Authentication
async function authApple(
  args: { account: string; password: string },
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<{ success: boolean; provider: string; account: string }> {
  await storage.set(memoryKey, { provider: 'apple', account: args.account, password: args.password });
  return { success: true, provider: 'apple', account: args.account };
}

/**
 * Instantiates a DAVClient using stored credentials.
 */
async function getDAVClient(config: Config, storage: Storage, memoryKey: string): Promise<DAVClient> {
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.provider || !stored.account) {
    throw new Error('No DAV credentials found. Please authenticate first.');
  }
  let client: DAVClient;
  if (stored.provider === 'google') {
    client = new DAVClient({
      serverUrl: 'https://apidata.googleusercontent.com/caldav/v2/',
      credentials: {
        tokenUrl: 'https://accounts.google.com/o/oauth2/token',
        username: stored.account,
        refreshToken: stored.refreshToken,
        clientId: config.googleClientId,
        clientSecret: config.googleClientSecret,
      },
      authMethod: 'Oauth',
      defaultAccountType: 'caldav',
    });
  } else if (stored.provider === 'apple') {
    client = new DAVClient({
      serverUrl: 'https://caldav.icloud.com',
      credentials: {
        username: stored.account,
        password: stored.password,
      },
      authMethod: 'Basic',
      defaultAccountType: 'caldav',
    });
  } else {
    throw new Error(`Unsupported provider: ${stored.provider}`);
  }
  await client.login();
  return client;
}

// --------------------------------------------------------------------
// CalDAV API Methods
// --------------------------------------------------------------------
async function fetchCalendarsTool(storage: Storage, config: Config, memoryKey: string) {
  const client = await getDAVClient(config, storage, memoryKey);
  return await client.fetchCalendars();
}

async function createCalendarObjectTool(
  args: { calendarUrl: string; data: string },
  storage: Storage,
  config: Config,
  memoryKey: string
) {
  const client = await getDAVClient(config, storage, memoryKey);
  const options = {
    calendar: { url: args.calendarUrl, props: {} },
    iCalString: args.data,
    filename: 'event.ics'
  };
  return await client.createCalendarObject(options);
}

/**
 * Helper: Automatically fetch the current etag for a calendar object.
 * It derives the calendar collection URL by removing the final segment from the event URL.
 */
async function getEtagForCalendarObject(
  eventUrl: string,
  storage: Storage,
  config: Config,
  memoryKey: string
): Promise<string> {
  const client = await getDAVClient(config, storage, memoryKey);
  const lastSlashIndex = eventUrl.lastIndexOf('/');
  if (lastSlashIndex === -1) {
    throw new Error('Invalid event URL.');
  }
  const collectionUrl = eventUrl.substring(0, lastSlashIndex + 1);
  const response = await client.fetchCalendarObjects({
    calendar: { url: collectionUrl, props: [{ name: 'getetag', namespace: DAVNamespace.DAV }] },
    objectUrls: [ eventUrl ],
    depth: "1" as DAVDepth
  } as any);
  if (response && response.length > 0 && response[0].etag) {
    return response[0].etag;
  }
  throw new Error(`Etag not found for calendar object at ${eventUrl}`);
}

async function updateCalendarObjectTool(
  args: { calendarObjectUrl: string; data: string },
  storage: Storage,
  config: Config,
  memoryKey: string
) {
  const client = await getDAVClient(config, storage, memoryKey);
  const etag = await getEtagForCalendarObject(args.calendarObjectUrl, storage, config, memoryKey);
  const calendarObject = { url: args.calendarObjectUrl, data: args.data, etag };
  return await client.updateCalendarObject({ calendarObject });
}

async function deleteCalendarObjectTool(
  args: { calendarObjectUrl: string },
  storage: Storage,
  config: Config,
  memoryKey: string
) {
  const client = await getDAVClient(config, storage, memoryKey);
  const etag = await getEtagForCalendarObject(args.calendarObjectUrl, storage, config, memoryKey);
  const calendarObject = { url: args.calendarObjectUrl, etag };
  return await client.deleteCalendarObject({ calendarObject });
}

async function fetchCalendarObjectsTool(
  args: { calendarUrl: string; timeRange: { start: string; end: string } },
  storage: Storage,
  config: Config,
  memoryKey: string
) {
  const client = await getDAVClient(config, storage, memoryKey);
  const calendar = { url: args.calendarUrl, props: {} };
  const options: any = { calendar, timeRange: args.timeRange };
  return await client.fetchCalendarObjects(options);
}

// --------------------------------------------------------------------
// MCP Server Creation: Register CalDAV Tools with Configurable Prefix
// --------------------------------------------------------------------
function createMcpServer(memoryKey: string, config: Config, toolsPrefix: string): McpServer {
  const server = new McpServer({
    name: `CalDAV MCP Server (Memory Key: ${memoryKey})`,
    version: '1.0.0'
  });
  const storage: Storage = config.storage === 'upstash-redis-rest'
    ? new RedisStorage(config.upstashRedisRestUrl!, config.upstashRedisRestToken!, config.storageHeaderKey!)
    : new MemoryStorage();

  server.tool(
    `${toolsPrefix}auth_url_google`,
    'Return an OAuth URL for Google Calendar (visit this URL to grant access).',
    {
      // TODO: MCP SDK bug patch - remove when fixed
      comment: z.string().optional(),
    },
    async () => {
      try {
        // Create a local OAuth2 client for generating the URL.
        const client = new OAuth2Client(config.googleClientId, config.googleClientSecret, config.googleRedirectUri);
        const url = client.generateAuthUrl({
          access_type: 'offline',
          prompt: 'consent',
          scope: ['https://www.googleapis.com/auth/calendar'],
          state: config.googleState
        });
        return toTextJson({ authUrl: url });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}auth_google`,
    'Authenticate for Google Calendar. Provide account (email) and auth code.',
    { account: z.string(), code: z.string() },
    async (args: { account: string; code: string }) => {
      try {
        const result = await authGoogle(args, config, storage, memoryKey);
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}auth_apple`,
    'Authenticate for Apple Calendar. Provide account (Apple ID) and password (app-specific password).',
    { account: z.string(), password: z.string() },
    async (args: { account: string; password: string }) => {
      try {
        const result = await authApple(args, config, storage, memoryKey);
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}fetch_calendars`,
    'Fetch all calendars for the authenticated account.',
    {
      // TODO: MCP SDK bug patch - remove when fixed
      comment: z.string().optional(),
    },
    async () => {
      try {
        const calendars = await fetchCalendarsTool(storage, config, memoryKey);
        return toTextJson(calendars);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}create_calendar_object`,
    'Create a new calendar event. Provide calendarUrl and event data (ICS format).',
    { calendarUrl: z.string(), data: z.string() },
    async (args: { calendarUrl: string; data: string }) => {
      try {
        const result = await createCalendarObjectTool(args, storage, config, memoryKey);
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}update_calendar_object`,
    'Update a calendar event. Provide calendarObjectUrl and new event data (ICS).',
    { calendarObjectUrl: z.string(), data: z.string() },
    async (args: { calendarObjectUrl: string; data: string }) => {
      try {
        const result = await updateCalendarObjectTool(args, storage, config, memoryKey);
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}delete_calendar_object`,
    'Delete a calendar event. Provide calendarObjectUrl.',
    { calendarObjectUrl: z.string() },
    async (args: { calendarObjectUrl: string }) => {
      try {
        const result = await deleteCalendarObjectTool(args, storage, config, memoryKey);
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}fetch_calendar_objects`,
    'Fetch calendar objects from a calendar. Provide calendarUrl and timeRange (start and end in ISO format).',
    { calendarUrl: z.string(), timeRange: z.object({ start: z.string(), end: z.string() }) },
    async (args: { calendarUrl: string; timeRange: { start: string; end: string } }) => {
      try {
        const objects = await fetchCalendarObjectsTool(args, storage, config, memoryKey);
        return toTextJson(objects);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  return server;
}

// --------------------------------------------------------------------
// Minimal Fly.io "replay" handling (optional)
// --------------------------------------------------------------------
function parseFlyReplaySrc(headerValue: string): Record<string, string> {
  const regex = /(.*?)=(.*?)($|;)/g;
  const matches = headerValue.matchAll(regex);
  const result: Record<string, string> = {};
  for (const match of matches) {
    if (match.length >= 3) {
      result[match[1].trim()] = match[2].trim();
    }
  }
  return result;
}
let machineId: string | null = null;
function saveMachineId(req: Request) {
  if (machineId) return;
  const headerKey = 'fly-replay-src';
  const raw = req.headers[headerKey.toLowerCase()];
  if (!raw || typeof raw !== 'string') return;
  try {
    const parsed = parseFlyReplaySrc(raw);
    if (parsed.state) {
      const decoded = decodeURIComponent(parsed.state);
      const obj = JSON.parse(decoded);
      if (obj.machineId) machineId = obj.machineId;
    }
  } catch {
    // ignore
  }
}

// --------------------------------------------------------------------
// Main: Start the server (SSE or stdio) with CLI validations
// --------------------------------------------------------------------
async function main() {
  const argv = yargs(hideBin(process.argv))
    .option('port', { type: 'number', default: 8000 })
    .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
    .option('storage', {
      type: 'string',
      choices: ['memory-single', 'memory', 'upstash-redis-rest'],
      default: 'memory-single',
      describe:
        'Choose storage backend: "memory-single" uses fixed single-user storage; "memory" uses multi-user in-memory storage (requires --storageHeaderKey); "upstash-redis-rest" uses Upstash Redis (requires --storageHeaderKey, --upstashRedisRestUrl, and --upstashRedisRestToken).'
    })
    .option('googleClientId', { type: 'string', demandOption: true, describe: "Google Client ID" })
    .option('googleClientSecret', { type: 'string', demandOption: true, describe: "Google Client Secret" })
    .option('googleRedirectUri', { type: 'string', demandOption: true, describe: "Google Redirect URI" })
    .option('googleState', { type: 'string', describe: "Optional Google OAuth state parameter" })
    .option('toolsPrefix', { type: 'string', default: 'caldav_', describe: 'Prefix to add to all tool names.' })
    .option('storageHeaderKey', { type: 'string', describe: 'For storage "memory" or "upstash-redis-rest": the header name (or key prefix) to use.' })
    .option('upstashRedisRestUrl', { type: 'string', describe: 'Upstash Redis REST URL (if --storage=upstash-redis-rest)' })
    .option('upstashRedisRestToken', { type: 'string', describe: 'Upstash Redis REST token (if --storage=upstash-redis-rest)' })
    .help()
    .parseSync();

  const config: Config = {
    port: argv.port,
    transport: argv.transport as 'sse' | 'stdio',
    storage: argv.storage as 'memory-single' | 'memory' | 'upstash-redis-rest',
    googleClientId: argv.googleClientId,
    googleClientSecret: argv.googleClientSecret,
    googleRedirectUri: argv.googleRedirectUri,
    googleState: (argv.googleState as string) || undefined,
    storageHeaderKey:
      (argv.storage === 'memory-single')
        ? undefined
        : (argv.storageHeaderKey && argv.storageHeaderKey.trim()
            ? argv.storageHeaderKey.trim()
            : (() => { console.error('Error: --storageHeaderKey is required for storage modes "memory" or "upstash-redis-rest".'); process.exit(1); return ''; })()),
    upstashRedisRestUrl: argv.upstashRedisRestUrl,
    upstashRedisRestToken: argv.upstashRedisRestToken,
  };

  // Additional CLI validation:
  if ((argv.upstashRedisRestUrl || argv.upstashRedisRestToken) && config.storage !== 'upstash-redis-rest') {
    console.error("Error: --upstashRedisRestUrl and --upstashRedisRestToken can only be used when --storage is 'upstash-redis-rest'.");
    process.exit(1);
  }
  if (config.storage === 'upstash-redis-rest') {
    if (!config.upstashRedisRestUrl || !config.upstashRedisRestUrl.trim()) {
      console.error("Error: --upstashRedisRestUrl is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
    if (!config.upstashRedisRestToken || !config.upstashRedisRestToken.trim()) {
      console.error("Error: --upstashRedisRestToken is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
  }

  const toolsPrefix: string = argv.toolsPrefix;

  if (config.transport === 'stdio') {
    const memoryKey = "single";
    const server = createMcpServer(memoryKey, config, toolsPrefix);
    const transport = new StdioServerTransport();
    void server.connect(transport);
    console.log('Listening on stdio');
    return;
  }

  const app = express();
  interface ServerSession {
    memoryKey: string;
    server: McpServer;
    transport: SSEServerTransport;
    sessionId: string;
  }
  let sessions: ServerSession[] = [];

  app.use((req, res, next) => {
    if (req.path === '/message') return next();
    express.json()(req, res, next);
  });

  app.get('/', async (req: Request, res: ExpressResponse) => {
    saveMachineId(req);
    let memoryKey: string;
    if (config.storage === 'memory-single') {
      memoryKey = "single";
    } else {
      const headerVal = req.headers[config.storageHeaderKey!.toLowerCase()];
      if (typeof headerVal !== 'string' || !headerVal.trim()) {
        res.status(400).json({ error: `Missing or invalid "${config.storageHeaderKey}" header` });
        return;
      }
      memoryKey = headerVal.trim();
    }
    const server = createMcpServer(memoryKey, config, toolsPrefix);
    const transport = new SSEServerTransport('/message', res);
    await server.connect(transport);
    const sessionId = transport.sessionId;
    sessions.push({ memoryKey, server, transport, sessionId });
    console.log(`[${sessionId}] SSE connected for key: "${memoryKey}"`);
    transport.onclose = () => {
      console.log(`[${sessionId}] SSE connection closed`);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    transport.onerror = (err: Error) => {
      console.error(`[${sessionId}] SSE error:`, err);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    req.on('close', () => {
      console.log(`[${sessionId}] Client disconnected`);
      sessions = sessions.filter(s => s.transport !== transport);
    });
  });

  app.post('/message', async (req: Request, res: ExpressResponse) => {
    const sessionId = req.query.sessionId as string;
    if (!sessionId) {
      console.error('Missing sessionId');
      res.status(400).send({ error: 'Missing sessionId' });
      return;
    }
    const target = sessions.find(s => s.sessionId === sessionId);
    if (!target) {
      console.error(`No active session for sessionId=${sessionId}`);
      res.status(404).send({ error: 'No active session' });
      return;
    }
    try {
      await target.transport.handlePostMessage(req, res);
    } catch (err: any) {
      console.error(`[${sessionId}] Error handling /message:`, err);
      res.status(500).send({ error: 'Internal error' });
    }
  });

  app.listen(config.port, () => {
    console.log(`Listening on port ${config.port} (${argv.transport})`);
  });
}

main().catch((err: any) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
