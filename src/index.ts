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

/**
 * Set up a DAV client for Google Calendar.
 *
 * Expects:
 *  - account: The Google account email.
 *  - refreshToken: The refresh token obtained via the auth code exchange.
 */
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

/**
 * Combined tool for Google: Exchange an auth code for a refresh token and set up the DAV client.
 *
 * Expects:
 *  - account: The Google account email.
 *  - code: The OAuth auth code.
 */
async function authGoogle(args: { account: string; code: string }) {
  const { account, code } = args
  const refreshToken = await exchangeAuthCode(code)
  return await setupGoogleDAV({ account, refreshToken })
}

/**
 * Set up a DAV client for Apple Calendar.
 *
 * Expects:
 *  - account: Your Apple ID.
 *  - password: Your app-specific password.
 */
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

/**
 * Fetch all calendars for the configured account.
 */
async function fetchCalendarsTool() {
  if (!davClient) {
    throw new Error('No DAV client configured. Run auth_google or auth_apple first.')
  }
  const calendars = await davClient.fetchCalendars()
  return calendars
}

/**
 * Query calendar events between start and end dates.
 *
 * Expects:
 *  - calendarUrl: The URL of the calendar to query.
 *  - start: ISO string for start date.
 *  - end: ISO string for end date.
 *
 * This tool constructs a filter based on a time-range on the VEVENT component.
 */
async function calendarQueryTool(args: { calendarUrl: string; start: string; end: string }) {
  if (!davClient) {
    throw new Error('No DAV client configured. Run auth_google or auth_apple first.')
  }
  const { calendarUrl, start, end } = args

  // Format date to CalDAV required format: YYYYMMDDTHHmmssZ (UTC)
  function formatDate(d: Date): string {
    const pad = (n: number) => n.toString().padStart(2, '0')
    return (
      d.getUTCFullYear().toString() +
      pad(d.getUTCMonth() + 1) +
      pad(d.getUTCDate()) +
      "T" +
      pad(d.getUTCHours()) +
      pad(d.getUTCMinutes()) +
      pad(d.getUTCSeconds()) +
      "Z"
    )
  }

  const startDate = new Date(start)
  const endDate = new Date(end)
  const startStr = formatDate(startDate)
  const endStr = formatDate(endDate)

  // Build a filter matching VEVENTs within the specified time range.
  const filters = [
    {
      "comp-filter": {
        _attributes: { name: "VCALENDAR" },
        "comp-filter": {
          _attributes: { name: "VEVENT" },
          "time-range": {
            _attributes: { start: startStr, end: endStr }
          }
        }
      }
    }
  ]

  const queryOptions = {
    url: calendarUrl,
    props: [{ name: 'getetag', namespace: DAVNamespace.DAV }],
    filters: filters,
    depth: "1" as DAVDepth,
  }

  const events = await davClient.calendarQuery(queryOptions)
  return events
}

/**
 * Create a new calendar event.
 *
 * Expects:
 *  - calendarUrl: The URL of the calendar to add the event.
 *  - data: The event data in iCalendar (ICS) format.
 */
async function createCalendarObjectTool(args: { calendarUrl: string; data: string }) {
  if (!davClient) {
    throw new Error('No DAV client configured. Run auth_google or auth_apple first.')
  }
  const { calendarUrl, data } = args
  const options = {
    calendar: {
      url: calendarUrl,
      props: {} // Add additional properties if required
    },
    iCalString: data,
    filename: 'event.ics'
  }
  const createdEvent = await davClient.createCalendarObject(options)
  return createdEvent
}

// --------------------------------------------------------------------
// 7) Create the MCP server, registering our tools
// --------------------------------------------------------------------
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: 'CalDAV MCP Server',
    version: '1.0.0'
  })

  // --- Google OAuth Tools ---
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

  // Combined tool: Exchange auth code and set up the Google DAV client.
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

  // --- DAV Client Setup Tool for Apple ---
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

  // --- DAV Operation Tools (assumes DAV client is set up) ---
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
    'calendar_query',
    'Query calendar events between two dates. Provide calendarUrl, start, and end (ISO strings).',
    {
      calendarUrl: z.string(),
      start: z.string(),
      end: z.string()
    },
    async (args) => {
      try {
        const events = await calendarQueryTool(args)
        return toTextJson(events)
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
