import type { ClaudeCodeMcpServer } from "../claude-code-mcp-loader/types"
import { NonInteractiveOAuthError } from "../mcp-oauth/oauth-authorization-flow"
import { McpOAuthProvider } from "../mcp-oauth/provider"
import { withRefreshMutex } from "../mcp-oauth/refresh-mutex"
import type { OAuthTokenData } from "../mcp-oauth/storage"
import { isStepUpRequired, mergeScopes } from "../mcp-oauth/step-up"
import { log } from "../../shared"
import type { OAuthProviderFactory, OAuthProviderLike } from "./types"

// Servers we've already logged a non-interactive OAuth skip for, so the
// warning isn't spammed on every subsequent request during the same session.
const nonInteractiveSkipLogged = new Set<string>()

function logNonInteractiveSkipOnce(serverUrl: string, error: NonInteractiveOAuthError): void {
  if (nonInteractiveSkipLogged.has(serverUrl)) return
  nonInteractiveSkipLogged.add(serverUrl)
  log(
    "[skill-mcp-manager] Skipping OAuth login for MCP server in non-interactive environment",
    { serverUrl, reason: error.message },
  )
}

export function getOrCreateAuthProvider(
  authProviders: Map<string, OAuthProviderLike>,
  serverUrl: string,
  oauth: NonNullable<ClaudeCodeMcpServer["oauth"]>,
  createOAuthProvider: OAuthProviderFactory = (options) => new McpOAuthProvider(options),
): OAuthProviderLike {
  const existing = authProviders.get(serverUrl)
  if (existing) return existing

  const provider = createOAuthProvider({
    serverUrl,
    clientId: oauth.clientId,
    scopes: oauth.scopes,
  })
  authProviders.set(serverUrl, provider)
  return provider
}

function isTokenExpired(tokenData: OAuthTokenData): boolean {
  if (tokenData.expiresAt == null) return false
  return tokenData.expiresAt < Math.floor(Date.now() / 1000)
}

export async function buildHttpRequestInit(
  config: ClaudeCodeMcpServer,
  authProviders: Map<string, OAuthProviderLike>,
  createOAuthProvider?: OAuthProviderFactory,
): Promise<RequestInit | undefined> {
  const headers: Record<string, string> = {}

  if (config.headers) {
    for (const [key, value] of Object.entries(config.headers)) {
      headers[key] = value
    }
  }

  if (config.oauth && config.url) {
    const provider = getOrCreateAuthProvider(authProviders, config.url, config.oauth, createOAuthProvider)
    let tokenData = provider.tokens()

    if (!tokenData) {
      try {
        tokenData = await provider.login()
      } catch (error) {
        if (error instanceof NonInteractiveOAuthError) {
          logNonInteractiveSkipOnce(config.url, error)
        }
        tokenData = null
      }
    }

      if (tokenData && isTokenExpired(tokenData)) {
        try {
          const refreshToken = tokenData.refreshToken
          tokenData = refreshToken
            ? await withRefreshMutex(config.url, () => provider.refresh(refreshToken))
            : await provider.login()
        } catch (outerError) {
          if (outerError instanceof NonInteractiveOAuthError) {
            logNonInteractiveSkipOnce(config.url, outerError)
            tokenData = null
          } else {
            try {
              tokenData = await provider.login()
            } catch (innerError) {
              if (innerError instanceof NonInteractiveOAuthError) {
                logNonInteractiveSkipOnce(config.url, innerError)
              }
              tokenData = null
            }
          }
      }
    }

    if (tokenData) {
      headers.Authorization = `Bearer ${tokenData.accessToken}`
    }
  }

  return Object.keys(headers).length > 0 ? { headers } : undefined
}

export async function handleStepUpIfNeeded(params: {
  error: Error
  config: ClaudeCodeMcpServer
  authProviders: Map<string, OAuthProviderLike>
  createOAuthProvider?: OAuthProviderFactory
}): Promise<boolean> {
  const { error, config, authProviders, createOAuthProvider } = params

  if (!config.oauth || !config.url) {
    return false
  }

  const statusMatch = /\b403\b/.exec(error.message)
  if (!statusMatch) {
    return false
  }

  const headers: Record<string, string> = {}
  const wwwAuthMatch = /WWW-Authenticate:\s*(.+)/i.exec(error.message)
  if (wwwAuthMatch?.[1]) {
    headers["www-authenticate"] = wwwAuthMatch[1]
  }

  const stepUp = isStepUpRequired(403, headers)
  if (!stepUp) {
    return false
  }

  const currentScopes = config.oauth.scopes ?? []
  const mergedScopes = mergeScopes(currentScopes, stepUp.requiredScopes)
  config.oauth.scopes = mergedScopes

  authProviders.delete(config.url)
  const provider = getOrCreateAuthProvider(authProviders, config.url, config.oauth, createOAuthProvider)

  try {
    await provider.login()
    return true
  } catch {
    return false
  }
}

export async function handlePostRequestAuthError(params: {
  error: Error
  config: ClaudeCodeMcpServer
  authProviders: Map<string, OAuthProviderLike>
  createOAuthProvider?: OAuthProviderFactory
  refreshAttempted?: Set<string>
}): Promise<boolean> {
  const { error, config, authProviders, createOAuthProvider, refreshAttempted = new Set() } = params

  if (!config.oauth || !config.url) {
    return false
  }

  const statusMatch = /\b(401|403)\b/.exec(error.message)
  if (!statusMatch) {
    return false
  }

  const provider = getOrCreateAuthProvider(authProviders, config.url, config.oauth, createOAuthProvider)
  const tokenData = provider.tokens()

  if (!tokenData?.refreshToken) {
    return false
  }

  if (refreshAttempted.has(config.url)) {
    return false
  }

  refreshAttempted.add(config.url)

  try {
    const refreshToken = tokenData.refreshToken
    await withRefreshMutex(config.url, () => provider.refresh(refreshToken))
    return true
  } catch {
    return false
  }
}
