// Shared secret redaction used by outbound gateways and error logging.
// Patterns originally authored in features/skill-mcp-manager/error-redaction.ts;
// promoted here so other modules (openclaw, logger adapters) can reuse them
// without cross-module imports into feature packages.

const SENSITIVE_PATTERNS: RegExp[] = [
  // API keys and tokens in common key=value / "key": "value" formats
  /[a-zA-Z0-9_-]*(?:api[_-]?key|apikey)["\s]*[:=]["\s]*([a-zA-Z0-9_-]{16,})/gi,
  /[a-zA-Z0-9_-]*(?:auth[_-]?token|authtoken)["\s]*[:=]["\s]*([a-zA-Z0-9_-]{16,})/gi,
  /[a-zA-Z0-9_-]*(?:access[_-]?token|accesstoken)["\s]*[:=]["\s]*([a-zA-Z0-9_-]{16,})/gi,
  /[a-zA-Z0-9_-]*(?:secret)["\s]*[:=]["\s]*([a-zA-Z0-9_-]{16,})/gi,
  /[a-zA-Z0-9_-]*(?:password)["\s]*[:=]["\s]*([a-zA-Z0-9_-]{8,})/gi,

  // Bearer tokens
  /bearer\s+([a-zA-Z0-9_-]{20,})/gi,

  // Common provider-issued tokens
  /sk-[a-zA-Z0-9]{20,}/g, // OpenAI / Anthropic style
  /gh[pousr]_[a-zA-Z0-9]{20,}/gi, // GitHub
  /glpat-[a-zA-Z0-9_-]{20,}/gi, // GitLab
  /xox[baprs]-[a-zA-Z0-9-]{20,}/gi, // Slack
  /AKIA[0-9A-Z]{16}/g, // AWS access keys
  /[A-Za-z0-9_]{20,}-[A-Za-z0-9_]{10,}-[A-Za-z0-9_]{10,}/g, // JWT-like triple
]

export const REDACTION_MARKER = "[REDACTED]"

/** Redacts likely credentials from a free-form string. Idempotent. */
export function redactSensitiveData(input: string): string {
  if (!input) return input
  let result = input
  for (const pattern of SENSITIVE_PATTERNS) {
    result = result.replace(pattern, REDACTION_MARKER)
  }
  return result
}

/** Returns a new Error with message + stack redacted. */
export function redactErrorSensitiveData(error: Error): Error {
  const redactedMessage = redactSensitiveData(error.message)
  const redactedError = new Error(redactedMessage)
  redactedError.stack = error.stack ? redactSensitiveData(error.stack) : undefined
  return redactedError
}
