import { lookup } from "node:dns/promises"
import { isIP } from "node:net"

// Mirrors the SSRF allowlist used by webfetch: only plain HTTP(S) is permitted.
// file://, gopher://, data://, ftp://, javascript:, etc. are rejected because
// fetch() can follow redirects into them and pull back sensitive content.
const ALLOWED_SCHEMES = new Set(["http:", "https:"])

// Integer helpers for IPv4 literal matching.
function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".")
  if (parts.length !== 4) return null
  let result = 0
  for (const part of parts) {
    const n = Number(part)
    if (!Number.isInteger(n) || n < 0 || n > 255) return null
    result = (result << 8) | n
  }
  return result >>> 0
}

// `&` in JavaScript returns a signed 32-bit integer, so `(addr & mask)` is
// negative whenever the top bit is set (i.e. any class-B/C/D/E range), while
// the compared literals like 0xa9fe0000 are positive Numbers > 2^31. The
// `>>> 0` shift re-interprets the bit pattern as unsigned 32-bit so the
// comparison is well-defined for the full 0.0.0.0-255.255.255.255 range.
function inCidr(addr: number, mask: number, network: number): boolean {
  return ((addr & mask) >>> 0) === network
}

function isIPv4Denied(ip: string): boolean {
  const addr = ipv4ToInt(ip)
  if (addr === null) return false

  // 0.0.0.0/8           "this" network
  if (inCidr(addr, 0xff000000, 0x00000000)) return true
  // 10.0.0.0/8          RFC1918 private
  if (inCidr(addr, 0xff000000, 0x0a000000)) return true
  // 127.0.0.0/8         loopback
  if (inCidr(addr, 0xff000000, 0x7f000000)) return true
  // 169.254.0.0/16      link-local (includes AWS 169.254.169.254, GCE metadata)
  if (inCidr(addr, 0xffff0000, 0xa9fe0000)) return true
  // 172.16.0.0/12       RFC1918 private
  if (inCidr(addr, 0xfff00000, 0xac100000)) return true
  // 192.0.0.0/24        IETF protocol assignments
  if (inCidr(addr, 0xffffff00, 0xc0000000)) return true
  // 192.0.2.0/24        TEST-NET-1
  if (inCidr(addr, 0xffffff00, 0xc0000200)) return true
  // 192.168.0.0/16      RFC1918 private
  if (inCidr(addr, 0xffff0000, 0xc0a80000)) return true
  // 198.18.0.0/15       benchmarking
  if (inCidr(addr, 0xfffe0000, 0xc6120000)) return true
  // 198.51.100.0/24     TEST-NET-2
  if (inCidr(addr, 0xffffff00, 0xc6336400)) return true
  // 203.0.113.0/24      TEST-NET-3
  if (inCidr(addr, 0xffffff00, 0xcb007100)) return true
  // 224.0.0.0/4         multicast
  if (inCidr(addr, 0xf0000000, 0xe0000000)) return true
  // 240.0.0.0/4         reserved (includes broadcast 255.255.255.255)
  if (inCidr(addr, 0xf0000000, 0xf0000000)) return true

  return false
}

function isIPv6Denied(ip: string): boolean {
  const normalized = ip.toLowerCase()

  // Unspecified
  if (normalized === "::" || normalized === "::0") return true
  // Loopback ::1
  if (normalized === "::1") return true
  // IPv4-mapped ::ffff:a.b.c.d - test the embedded IPv4
  const v4Mapped = normalized.match(/^::ffff:([0-9.]+)$/)
  if (v4Mapped && v4Mapped[1] && isIPv4Denied(v4Mapped[1])) return true
  // Link-local fe80::/10
  if (/^fe[89ab][0-9a-f]?:/.test(normalized)) return true
  // Unique local fc00::/7
  if (/^f[cd][0-9a-f]{0,2}:/.test(normalized)) return true
  // Multicast ff00::/8
  if (normalized.startsWith("ff")) return true
  // Site-local fec0::/10 (deprecated but still private)
  if (/^fe[cdef][0-9a-f]?:/.test(normalized)) return true

  return false
}

/**
 * Returns true when a literal IP address belongs to a private, loopback,
 * link-local, multicast, or otherwise non-public range that webfetch must not
 * reach (AWS metadata, localhost dev servers, RFC1918 internal networks, etc.).
 */
export function isDeniedIp(ip: string): boolean {
  const family = isIP(ip)
  if (family === 4) return isIPv4Denied(ip)
  if (family === 6) return isIPv6Denied(ip)
  return false
}

export type SsrfCheckResult =
  | { ok: true }
  | { ok: false; reason: string }

/**
 * Validate that a URL is safe for outbound fetch:
 *  - scheme must be http/https (blocks file://, gopher://, data:, etc.)
 *  - hostname must resolve only to public IP addresses (blocks SSRF to
 *    loopback, RFC1918, link-local, metadata services, multicast)
 *
 * Both literal IPs (short-circuit DNS) and domain names (resolve via DNS)
 * are validated. All resolved addresses must be public - any single private
 * address in the DNS answer is treated as denial.
 */
export async function checkUrlSafeForFetch(rawUrl: string): Promise<SsrfCheckResult> {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    return { ok: false, reason: `invalid URL: ${rawUrl}` }
  }

  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    return {
      ok: false,
      reason: `scheme ${parsed.protocol} is not allowed (only http/https)`,
    }
  }

  const hostname = parsed.hostname
  if (!hostname) return { ok: false, reason: "URL has no hostname" }

  // Strip IPv6 brackets for the isIP check.
  const bareHost = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname

  // Literal IP: no DNS lookup required.
  if (isIP(bareHost)) {
    if (isDeniedIp(bareHost)) {
      return { ok: false, reason: `target IP ${bareHost} is in a blocked range` }
    }
    return { ok: true }
  }

  // Hostname: resolve all families and reject if any address is private.
  try {
    const addresses = await lookup(bareHost, { all: true, verbatim: true })
    if (addresses.length === 0) {
      return { ok: false, reason: `hostname ${bareHost} did not resolve to any address` }
    }
    for (const entry of addresses) {
      if (isDeniedIp(entry.address)) {
        return {
          ok: false,
          reason: `hostname ${bareHost} resolves to blocked address ${entry.address}`,
        }
      }
    }
    return { ok: true }
  } catch (error) {
    return {
      ok: false,
      reason: `DNS lookup failed for ${bareHost}: ${error instanceof Error ? error.message : String(error)}`,
    }
  }
}
