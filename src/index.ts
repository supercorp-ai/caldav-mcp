#!/usr/bin/env ts-node

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import express, { Request, Response } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { google } from 'googleapis'
import { OAuth2Client } from 'google-auth-library'
import { DAVClient, DAVNamespace, DAVDepth } from 'tsdav'

// --------------------------------------------------------------------
// 1) Parse CLI options (including Google credentials)
// --------------------------------------------------------------------
const argv = yargs(hideBin(process.argv))
  .option('port', { type: 'number', default: 8000 })
  .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
  .option('googleClientId', { type: 'string', demandOption: true, describe: "Google Client ID" })
  .option('googleClientSecret', { type: 'string', demandOption: true, describe: "Google Client Secret" })
  .option('googleRedirectUri', { type: 'string', demandOption: true, describe: "Google Redirect URI" })
  .option('googleState', { type: 'string', default: '', describe: "Google State (optional)" })
  .help()
  .parseSync()

const log = (...args: any[]) => console.log('[caldav-mcp]', ...args)
const logErr = (...args: any[]) => console.error('[caldav-mcp]', ...args)

// --------------------------------------------------------------------
// 2) Global DAV client state
// --------------------------------------------------------------------
let davClient: DAVClient | null = null
let davClientType: "google" | "apple" | null = null

// --------------------------------------------------------------------
// 3) Google OAuth Setup (for Google DAV client)
// --------------------------------------------------------------------
const GOOGLE_CLIENT_ID = argv.googleClientId
const GOOGLE_CLIENT_SECRET = argv.googleClientSecret
const GOOGLE_REDIRECT_URI = argv.googleRedirectUri
const GOOGLE_STATE = argv.googleState

const oauth2Client = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI)

// Helper to get a current access token (Google)
async function getGoogleAccessToken(): Promise<string> {
  const res = await oauth2Client.getAccessToken()
  if (!res.token) {
    throw new Error('Failed to obtain Google access token.')
  }
  return res.token
}

// Exchange auth code for refresh token (Google only)
async function exchangeAuthCode(code: string): Promise<string> {
  log(`Exchanging Google auth code: ${code}`)
  const { tokens } = await oauth2Client.getToken(code.trim())
  if (!tokens.refresh_token) {
    throw new Error('No refresh token returned by Google.')
  }
  oauth2Client.setCredentials(tokens)
  return tokens.refresh_token
}

// --------------------------------------------------------------------
// 4) Helper: JSON response formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(data, null, 2)
      }
    ]
  }
}

// --------------------------------------------------------------------
// 5) Tool Functions: Setting up DAV client
// --------------------------------------------------------------------
async function setupGoogleDAV(args: { account: string; refreshToken: string }) {
  const { account, refreshToken } = args
  const client = new DAVClient({
    serverUrl: 'https://apidata.googleusercontent.com/caldav/v2/',
    credentials: {
      tokenUrl: 'https://accounts.google.com/o/oauth2/token',
      username: account,
      refreshToken: refreshToken,
      clientId: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
    },
    authMethod: 'Oauth',
    defaultAccountType: 'caldav',
  })
  await client.login()
  davClient = client
  davClientType = "google"
  return { success: true, provider: "google", account }
}

async function authGoogle(args: { account: string; code: string }) {
  const { account, code } = args
  const refreshToken = await exchangeAuthCode(code)
  return await setupGoogleDAV({ account, refreshToken })
}

async function authApple(args: { account: string; password: string }) {
  const { account, password } = args
  const client = new DAVClient({
    serverUrl: 'https://caldav.icloud.com',
    credentials: {
      username: account,
      password: password,
    },
    authMethod: 'Basic',
    defaultAccountType: 'caldav',
  })
  await client.login()
  davClient = client
  davClientType = "apple"
  return { success: true, provider: "apple", account }
}

// --------------------------------------------------------------------
// 6) Tool Functions: DAV Operations using the global DAV client
// --------------------------------------------------------------------
async function fetchCalendarsTool() {
  if (!davClient) {
    throw new Error('No DAV client configured. Run auth_google or auth_apple first.')
  }
  return await davClient.fetchCalendars()
}

async function createCalendarObjectTool(args: { calendarUrl: string; data: string }) {
  if (!davClient) {
    throw new Error('No DAV client configured. Run auth_google or auth_apple first.')
  }
  const { calendarUrl, data } = args
  const options = {
    calendar: { url: calendarUrl, props: {} },
    iCalString: data,
    filename: 'event.ics'
  }
  return await davClient.createCalendarObject(options)
}

/**
 * Helper: Automatically fetch the current etag for a calendar object URL.
 * It derives the calendar collection URL by removing the final segment from the event URL.
 */
async function getEtagForCalendarObject(eventUrl: string): Promise<string> {
  if (!davClient) {
    throw new Error('No DAV client configured. Run auth_google or auth_apple first.')
  }
  const lastSlashIndex = eventUrl.lastIndexOf('/');
  if (lastSlashIndex === -1) {
    throw new Error('Invalid event URL.')
  }
  const calendarUrl = eventUrl.substring(0, lastSlashIndex + 1);
  const response = await davClient.fetchCalendarObjects({ calendar: { url: calendarUrl, props: {} }, objectUrls: [eventUrl] } as any)
  if (response && response.length > 0 && response[0].etag) {
    return response[0].etag
  }
  throw new Error(`Etag not found for calendar object at ${eventUrl}`)
}

async function updateCalendarObjectTool(args: { calendarObjectUrl: string; data: string; }) {
  if (!davClient) {
    throw new Error('No DAV client configured. Run auth_google or auth_apple first.')
  }
  const { calendarObjectUrl, data } = args
  const etag = await getEtagForCalendarObject(calendarObjectUrl)
  const calendarObject = { url: calendarObjectUrl, data, etag }
  return await davClient.updateCalendarObject({ calendarObject })
}

async function deleteCalendarObjectTool(args: { calendarObjectUrl: string; }) {
  if (!davClient) {
    throw new Error('No DAV client configured. Run auth_google or auth_apple first.')
  }
  const { calendarObjectUrl } = args
  const etag = await getEtagForCalendarObject(calendarObjectUrl)
  const calendarObject = { url: calendarObjectUrl, etag }
  return await davClient.deleteCalendarObject({ calendarObject })
}

/**
 * New Tool: Fetch calendar objects.
 * Expects:
 *  - calendarUrl: The URL of the calendar.
 *  - timeRange: An object with timeRange.start and timeRange.end in ISO 8601 format.
 */
async function fetchCalendarObjectsTool(args: { calendarUrl: string; timeRange: { start: string; end: string } }) {
  if (!davClient) {
    throw new Error('No DAV client configured. Run auth_google or auth_apple first.')
  }
  const { calendarUrl, timeRange } = args
  const calendar = { url: calendarUrl, props: {} }
  const options: any = { calendar, timeRange }
  return await davClient.fetchCalendarObjects(options)
}

// --------------------------------------------------------------------
// 7) Create the MCP server, registering our tools
// --------------------------------------------------------------------
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: 'CalDAV MCP Server',
    version: '1.0.0'
  })

  server.tool(
    'auth_url_google',
    'Return an OAuth URL for Google Calendar (visit this URL to grant access).',
    {},
    async () => {
      try {
        const authUrl = oauth2Client.generateAuthUrl({
          access_type: 'offline',
          prompt: 'consent',
          scope: ['https://www.googleapis.com/auth/calendar'],
          state: GOOGLE_STATE
        })
        return toTextJson({ authUrl })
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'auth_google',
    'Set up the DAV client for Google Calendar by exchanging an auth code and providing the account (email).',
    {
      account: z.string(),
      code: z.string()
    },
    async (args) => {
      try {
        const result = await authGoogle(args)
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'auth_apple',
    'Set up the DAV client for Apple Calendar. Provide account (Apple ID) and password (app-specific password).',
    {
      account: z.string(),
      password: z.string()
    },
    async (args) => {
      try {
        const result = await authApple(args)
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'fetch_calendars',
    'Fetch all calendars for the configured account.',
    {},
    async () => {
      try {
        const calendars = await fetchCalendarsTool()
        return toTextJson(calendars)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'create_calendar_object',
    'Create a new calendar event. Provide calendarUrl and event data in iCalendar (ICS) format.',
    {
      calendarUrl: z.string(),
      data: z.string()
    },
    async (args) => {
      try {
        const result = await createCalendarObjectTool(args)
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'update_calendar_object',
    'Update a calendar event. Provide calendarObjectUrl and new event data (ICS).',
    {
      calendarObjectUrl: z.string(),
      data: z.string()
    },
    async (args) => {
      try {
        const result = await updateCalendarObjectTool(args as { calendarObjectUrl: string; data: string })
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'delete_calendar_object',
    'Delete a calendar event. Provide calendarObjectUrl.',
    {
      calendarObjectUrl: z.string()
    },
    async (args) => {
      try {
        const result = await deleteCalendarObjectTool(args as { calendarObjectUrl: string })
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'fetch_calendar_objects',
    'Fetch calendar objects from a given calendar. Provide calendarUrl and timeRange with start and end in ISO 8601 format.',
    {
      calendarUrl: z.string(),
      timeRange: z.object({ start: z.string(), end: z.string() })
    },
    async (args) => {
      try {
        const objects = await fetchCalendarObjectsTool(args as { calendarUrl: string; timeRange: { start: string; end: string } })
        return toTextJson(objects)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  return server
}

// --------------------------------------------------------------------
// 8) Minimal Fly.io "replay" handling (optional)
// --------------------------------------------------------------------
function parseFlyReplaySrc(headerValue: string): Record<string, string> {
  const regex = /(.*?)=(.*?)($|;)/g
  const matches = headerValue.matchAll(regex)
  const result: Record<string, string> = {}
  for (const match of matches) {
    if (match.length >= 3) {
      const key = match[1].trim()
      const value = match[2].trim()
      result[key] = value
    }
  }
  return result
}
let machineId: string | null = null
function saveMachineId(req: Request) {
  if (machineId) return
  const headerKey = 'fly-replay-src'
  const raw = req.headers[headerKey.toLowerCase()]
  if (!raw || typeof raw !== 'string') return
  try {
    const parsed = parseFlyReplaySrc(raw)
    if (parsed.state) {
      const decoded = decodeURIComponent(parsed.state)
      const obj = JSON.parse(decoded)
      if (obj.machineId) machineId = obj.machineId
    }
  } catch {
    // ignore
  }
}

// --------------------------------------------------------------------
// 9) Main: Start either SSE or stdio server
// --------------------------------------------------------------------
function main() {
  const server = createMcpServer()

  if (argv.transport === 'stdio') {
    const transport = new StdioServerTransport()
    void server.connect(transport)
    log('Listening on stdio')
    return
  }

  const port = argv.port
  const app = express()
  let sessions: { server: McpServer; transport: SSEServerTransport }[] = []

  app.use((req, res, next) => {
    if (req.path === '/message') return next()
    express.json()(req, res, next)
  })

  app.get('/', async (req: Request, res: Response) => {
    saveMachineId(req)
    const transport = new SSEServerTransport('/message', res)
    const mcpInstance = createMcpServer()
    await mcpInstance.connect(transport)
    sessions.push({ server: mcpInstance, transport })

    const sessionId = transport.sessionId
    log(`[${sessionId}] SSE connection established`)

    transport.onclose = () => {
      log(`[${sessionId}] SSE closed`)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    req.on('close', () => {
      log(`[${sessionId}] SSE client disconnected`)
      sessions = sessions.filter(s => s.transport !== transport)
    })
  })

  app.post('/message', async (req: Request, res: Response) => {
    const sessionId = req.query.sessionId as string
    if (!sessionId) {
      logErr('Missing sessionId')
      res.status(400).send({ error: 'Missing sessionId' })
      return
    }
    const target = sessions.find(s => s.transport.sessionId === sessionId)
    if (!target) {
      logErr(`No active session for sessionId=${sessionId}`)
      res.status(404).send({ error: 'No active session' })
      return
    }
    try {
      await target.transport.handlePostMessage(req, res)
    } catch (err: any) {
      logErr(`[${sessionId}] Error handling /message:`, err)
      res.status(500).send({ error: 'Internal error' })
    }
  })

  app.listen(port, () => {
    log(`Listening on port ${port} (${argv.transport})`)
  })
}

main()
