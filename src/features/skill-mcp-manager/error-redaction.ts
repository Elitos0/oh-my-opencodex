// Re-exports shared secret redaction so existing call-sites inside
// skill-mcp-manager keep working. Canonical implementation now lives in
// src/shared/secret-redaction.ts so non-feature modules can reuse it.
export { redactSensitiveData, redactErrorSensitiveData } from "../../shared/secret-redaction"
