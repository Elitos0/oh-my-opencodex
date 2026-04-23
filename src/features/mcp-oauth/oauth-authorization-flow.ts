import { spawn } from "node:child_process"
import { createHash, randomBytes } from "node:crypto"
import { createServer } from "node:http"

export type OAuthCallbackResult = {
  code: string
  state: string
}

export function generateCodeVerifier(): string {
  return randomBytes(32).toString("base64url")
}

export function generateCodeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url")
}

export function buildAuthorizationUrl(
  authorizationEndpoint: string,
  options: {
    clientId: string
    redirectUri: string
    codeChallenge: string
    state: string
    scopes?: string[]
    resource?: string
  }
): string {
  const url = new URL(authorizationEndpoint)
  url.searchParams.set("response_type", "code")
  url.searchParams.set("client_id", options.clientId)
  url.searchParams.set("redirect_uri", options.redirectUri)
  url.searchParams.set("code_challenge", options.codeChallenge)
  url.searchParams.set("code_challenge_method", "S256")
  url.searchParams.set("state", options.state)
  if (options.scopes && options.scopes.length > 0) {
    url.searchParams.set("scope", options.scopes.join(" "))
  }
  if (options.resource) {
    url.searchParams.set("resource", options.resource)
  }
  return url.toString()
}

const CALLBACK_TIMEOUT_MS = 5 * 60 * 1000
const CALLBACK_PATH = "/callback"

export function startCallbackServer(port: number, expectedState?: string): Promise<OAuthCallbackResult> {
  return new Promise((resolve, reject) => {
    let timeoutId: ReturnType<typeof setTimeout>

    const server = createServer((request, response) => {
      const requestUrl = new URL(request.url ?? "/", `http://localhost:${port}`)

      if (requestUrl.pathname !== CALLBACK_PATH) {
        response.writeHead(404, { "content-type": "text/plain" })
        response.end("Not Found")
        return
      }

      clearTimeout(timeoutId)

      const code = requestUrl.searchParams.get("code")
      const state = requestUrl.searchParams.get("state")
      const error = requestUrl.searchParams.get("error")

      if (error) {
        const errorDescription = requestUrl.searchParams.get("error_description") ?? error
        response.writeHead(400, { "content-type": "text/html" })
        response.end("<html><body><h1>Authorization failed</h1></body></html>")
        server.close()
        reject(new Error(`OAuth authorization error: ${errorDescription}`))
        return
      }

      if (!code || !state) {
        response.writeHead(400, { "content-type": "text/html" })
        response.end("<html><body><h1>Missing code or state</h1></body></html>")
        server.close()
        reject(new Error("OAuth callback missing code or state parameter"))
        return
      }

      if (expectedState !== undefined && state !== expectedState) {
        response.writeHead(400, { "content-type": "text/html" })
        response.end("<html><body><h1>Invalid state</h1></body></html>")
        server.close()
        reject(new Error("OAuth state mismatch"))
        return
      }

      response.writeHead(200, { "content-type": "text/html" })
      response.end("<html><body><h1>Authorization successful. You can close this tab.</h1></body></html>")
      server.close()
      resolve({ code, state })
    })

    timeoutId = setTimeout(() => {
      server.close()
      reject(new Error("OAuth callback timed out after 5 minutes"))
    }, CALLBACK_TIMEOUT_MS)

    server.listen(port, "127.0.0.1")
    server.on("error", (err) => {
      clearTimeout(timeoutId)
      reject(err)
    })
  })
}

function openBrowser(url: string): void {
  const platform = process.platform
  let command: string
  let args: string[]

  if (platform === "darwin") {
    command = "open"
    args = [url]
  } else if (platform === "win32") {
    command = "explorer"
    args = [url]
  } else {
    command = "xdg-open"
    args = [url]
  }

  try {
    const child = spawn(command, args, { stdio: "ignore", detached: true })
    child.on("error", () => {})
    child.unref()
  } catch {
    // Browser open failed - user must navigate manually
  }
}

/**
 * Returns true when the current process has no interactive user attached, so
 * an OAuth browser round-trip cannot complete. Detects:
 *  - CI runners (CI, GITHUB_ACTIONS, BUILDKITE, CIRCLECI, GITLAB_CI, ...)
 *  - opencode's explicit OPENCODE_NON_INTERACTIVE flag (set by `opencode run`)
 *  - subagent / background-task launches (OPENCODE_SUBAGENT=1)
 *  - detached stdin/stdout (no TTY on either side)
 */
export function isNonInteractiveEnvironment(): boolean {
  const env = process.env
  if (env.OPENCODE_NON_INTERACTIVE === "1" || env.OPENCODE_NON_INTERACTIVE === "true") {
    return true
  }
  if (env.OPENCODE_SUBAGENT === "1" || env.OPENCODE_SUBAGENT === "true") {
    return true
  }
  if (env.CI && env.CI !== "false" && env.CI !== "0") return true
  if (env.GITHUB_ACTIONS || env.BUILDKITE || env.CIRCLECI || env.GITLAB_CI || env.JENKINS_URL) {
    return true
  }
  // Both stdin and stdout detached -> no human on the other end.
  const stdinTty = Boolean(process.stdin.isTTY)
  const stdoutTty = Boolean(process.stdout.isTTY)
  if (!stdinTty && !stdoutTty) return true
  return false
}

export class NonInteractiveOAuthError extends Error {
  constructor(authorizationUrl: string) {
    super(
      `Cannot complete OAuth authorization in a non-interactive environment. ` +
        `A human must open the authorization URL in a browser and approve access. ` +
        `Run \`bunx oh-my-opencode mcp-oauth login <server>\` from an interactive terminal, ` +
        `or pre-seed the token file under ~/.config/opencode/mcp-oauth/. ` +
        `Authorization URL (for manual completion): ${authorizationUrl}`,
    )
    this.name = "NonInteractiveOAuthError"
  }
}

export async function runAuthorizationCodeRedirect(options: {
  authorizationEndpoint: string
  callbackPort: number
  clientId: string
  redirectUri: string
  scopes?: string[]
  resource?: string
}): Promise<{ code: string; verifier: string }> {
  const verifier = generateCodeVerifier()
  const challenge = generateCodeChallenge(verifier)
  const state = randomBytes(16).toString("hex")

  const authorizationUrl = buildAuthorizationUrl(options.authorizationEndpoint, {
    clientId: options.clientId,
    redirectUri: options.redirectUri,
    codeChallenge: challenge,
    state,
    scopes: options.scopes,
    resource: options.resource,
  })

  // Fast-fail before binding the callback server and waiting 5 minutes: a
  // subagent / CI run has no browser or human to press the consent button,
  // so the only outcome of waiting is hanging the caller until timeout
  // (and then retrying 3 times on 401 = 15 minute stall per MCP server).
  if (isNonInteractiveEnvironment()) {
    throw new NonInteractiveOAuthError(authorizationUrl)
  }

  const callbackPromise = startCallbackServer(options.callbackPort, state)
  openBrowser(authorizationUrl)

  const result = await callbackPromise
  return { code: result.code, verifier }
}
