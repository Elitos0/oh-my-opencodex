import { spawn } from "bun"
import { randomBytes } from "node:crypto"

// User-option name on the tmux pane. `@` prefix is required by tmux for
// user-defined options. We intentionally pick an opencode-specific name so
// unrelated panes (attacker-controlled or otherwise) cannot collide by
// accident.
const PANE_NONCE_OPTION = "@opencode-pane-nonce"

export function generatePaneNonce(): string {
  // 128 bits of entropy is plenty; base64url keeps it tmux-option-safe
  // (tmux user-options are shell-quoted but safer with no special chars).
  return randomBytes(16).toString("base64url")
}

export async function setPaneNonce(paneId: string, nonce: string): Promise<boolean> {
  try {
    const proc = spawn(
      ["tmux", "set-option", "-p", "-t", paneId, PANE_NONCE_OPTION, nonce],
      { stdout: "ignore", stderr: "ignore" },
    )
    await proc.exited
    return proc.exitCode === 0
  } catch {
    return false
  }
}

export async function getPaneNonce(paneId: string): Promise<string | null> {
  try {
    // `show-options -p -v -t <pane> <name>` prints just the value (or empty
    // and non-zero exit when unset). Using -v avoids the "name value" format.
    const proc = spawn(
      ["tmux", "show-options", "-p", "-v", "-t", paneId, PANE_NONCE_OPTION],
      { stdout: "pipe", stderr: "ignore" },
    )
    const outputPromise = new Response(proc.stdout).text()
    await proc.exited
    const output = await outputPromise
    if (proc.exitCode !== 0) return null
    const trimmed = output.trim()
    return trimmed.length > 0 ? trimmed : null
  } catch {
    return null
  }
}

/**
 * Timing-safe string comparison. The nonce is stored in a tmux pane option,
 * so leaked timing cannot be directly measured across the network, but we
 * still avoid early-exit compare to be defensive.
 */
export function nonceEquals(a: string | null | undefined, b: string | null | undefined): boolean {
  if (!a || !b) return false
  if (a.length !== b.length) return false
  let mismatch = 0
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return mismatch === 0
}

/**
 * Ensure the given pane carries a nonce; if it already has one, return it;
 * otherwise generate a fresh nonce, set it on the pane, and return it.
 * Returns null if tmux is unavailable or the pane cannot be stamped.
 */
export async function ensurePaneNonce(paneId: string): Promise<string | null> {
  const existing = await getPaneNonce(paneId)
  if (existing) return existing
  const fresh = generatePaneNonce()
  const ok = await setPaneNonce(paneId, fresh)
  return ok ? fresh : null
}
