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

/**
 * Expand an IPv6 address string to its full 8-group hex form. Accepts any
 * valid IPv6 literal (with or without `::`, with or without an embedded
 * dotted-decimal IPv4 tail). Returns null for malformed input.
 *
 * Example:
 *   "::1"                       -> [0, 0, 0, 0, 0, 0, 0, 1]
 *   "::ffff:7f00:1"             -> [0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001]
 *   "::ffff:127.0.0.1"          -> [0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001]
 *   "0:0:0:0:0:ffff:7f00:1"     -> [0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001]
 */
function expandIPv6(ip: string): number[] | null {
  // Split off any `::` so we can count groups on each side.
  const doubleColonParts = ip.split("::")
  if (doubleColonParts.length > 2) return null

  const parseSide = (side: string): number[] | null => {
    if (side === "") return []
    const groups = side.split(":")
    const result: number[] = []
    for (let i = 0; i < groups.length; i++) {
      const g = groups[i] ?? ""
      // Dotted-quad IPv4 tail is only legal in the last segment.
      if (g.includes(".")) {
        if (i !== groups.length - 1) return null
        const octets = g.split(".")
        if (octets.length !== 4) return null
        const bytes: number[] = []
        for (const octet of octets) {
          const n = Number(octet)
          if (!Number.isInteger(n) || n < 0 || n > 255) return null
          bytes.push(n)
        }
        result.push((bytes[0]! << 8) | bytes[1]!)
        result.push((bytes[2]! << 8) | bytes[3]!)
        continue
      }
      if (g.length === 0 || g.length > 4) return null
      if (!/^[0-9a-f]+$/.test(g)) return null
      result.push(parseInt(g, 16))
    }
    return result
  }

  const headRaw = doubleColonParts[0] ?? ""
  const tailRaw = doubleColonParts.length === 2 ? (doubleColonParts[1] ?? "") : ""
  const head = parseSide(headRaw)
  if (head === null) return null
  const tail = parseSide(tailRaw)
  if (tail === null) return null

  if (doubleColonParts.length === 2) {
    const zeroFill = 8 - head.length - tail.length
    if (zeroFill < 0) return null
    return [...head, ...new Array(zeroFill).fill(0), ...tail]
  }
  return head.length === 8 ? head : null
}

function isIPv6Denied(ip: string): boolean {
  const normalized = ip.toLowerCase()

  // IPv6 ranges are checked against the fully-expanded 8-group form so
  // that abbreviated spellings (e.g. `fe8::1` which expands to
  // `0fe8:0:0:0:0:0:0:1` and is NOT in fe80::/10) cannot false-positive
  // against a regex that only sees the leading characters of the source
  // string. This also canonicalises `::`, `::1`, and every IPv4-mapped
  // representation to the same structural check.
  const groups = expandIPv6(normalized)
  if (groups === null) {
    // Node's isIP() returned 6 but our expander didn't accept it. Fail
    // closed: treat the address as denied rather than risk a bypass.
    return true
  }

  const g0 = groups[0]!
  const g1 = groups[1]!
  const g2 = groups[2]!
  const g3 = groups[3]!
  const g4 = groups[4]!
  const g5 = groups[5]!
  const g6 = groups[6]!
  const g7 = groups[7]!

  const firstSixZero = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0
  // Unspecified :: and loopback ::1
  if (firstSixZero && g5 === 0 && g6 === 0 && g7 === 0) return true
  if (firstSixZero && g5 === 0 && g6 === 0 && g7 === 1) return true

  // IPv4-mapped (::ffff:0:0/96) and deprecated IPv4-compatible (::/96)
  // prefixes -- extract the low 32 bits as a dotted-quad and delegate to
  // isIPv4Denied so every representation inherits the v4 denylist.
  if (firstSixZero && (g5 === 0xffff || (g5 === 0 && (g6 !== 0 || g7 !== 0)))) {
    const mapped = `${(g6 >>> 8) & 0xff}.${g6 & 0xff}.${(g7 >>> 8) & 0xff}.${g7 & 0xff}`
    if (isIPv4Denied(mapped)) return true
  }

  // First-group CIDR checks on the fully-expanded value. Using integer
  // range comparisons removes the abbreviation-sensitive regex false
  // positives (e.g. `fe8::1` expands to g0=0x0fe8 which is NOT link-local
  // but was matched by /^fe[89ab][0-9a-f]?:/).
  // Link-local fe80::/10  -> g0 in [0xfe80, 0xfebf]
  if (g0 >= 0xfe80 && g0 <= 0xfebf) return true
  // Site-local fec0::/10  -> g0 in [0xfec0, 0xfeff] (deprecated but still private)
  if (g0 >= 0xfec0 && g0 <= 0xfeff) return true
  // Unique local fc00::/7 -> g0 in [0xfc00, 0xfdff]
  if (g0 >= 0xfc00 && g0 <= 0xfdff) return true
  // Multicast ff00::/8    -> g0 in [0xff00, 0xffff]
  if (g0 >= 0xff00 && g0 <= 0xffff) return true

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
