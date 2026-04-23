import { describe, test, expect } from "bun:test"
import { isDeniedIp } from "./ssrf-guard"

describe("isDeniedIp", () => {
  // Regression: JS `&` returns signed int32, so ranges starting at 128.0.0.0
  // and above silently slipped through an earlier version of this guard.
  describe("IPv4 private / loopback / metadata ranges", () => {
    const deniedCases: Array<[string, string]> = [
      ["127.0.0.1", "loopback"],
      ["127.255.255.254", "loopback edge"],
      ["10.0.0.1", "RFC1918 10/8"],
      ["10.255.255.255", "RFC1918 10/8 edge"],
      ["169.254.169.254", "AWS metadata"],
      ["169.254.170.2", "ECS metadata"],
      ["169.254.0.1", "link-local low edge"],
      ["172.16.0.1", "RFC1918 172.16/12 low edge"],
      ["172.31.255.254", "RFC1918 172.16/12 high edge"],
      ["192.168.0.1", "RFC1918 192.168/16"],
      ["192.168.255.254", "RFC1918 192.168/16 high edge"],
      ["192.0.2.1", "TEST-NET-1"],
      ["198.18.0.1", "benchmarking 198.18/15 low"],
      ["198.19.255.254", "benchmarking 198.18/15 high"],
      ["198.51.100.1", "TEST-NET-2"],
      ["203.0.113.1", "TEST-NET-3"],
      ["224.0.0.1", "multicast"],
      ["239.255.255.255", "multicast high"],
      ["240.0.0.1", "reserved"],
      ["255.255.255.255", "broadcast"],
      ["0.0.0.0", "unspecified / this-network"],
    ]
    for (const [ip, description] of deniedCases) {
      test(`${ip} (${description}) is denied`, () => {
        expect(isDeniedIp(ip)).toBe(true)
      })
    }
  })

  describe("IPv4 public addresses are allowed", () => {
    const allowedCases = [
      "1.1.1.1",
      "8.8.8.8",
      "9.9.9.9",
      "172.15.255.255",
      "172.32.0.0",
      "192.167.255.255",
      "192.169.0.0",
      "198.17.255.255",
      "198.20.0.0",
      "223.255.255.255",
    ]
    for (const ip of allowedCases) {
      test(`${ip} is allowed`, () => {
        expect(isDeniedIp(ip)).toBe(false)
      })
    }
  })

  describe("IPv6 denied ranges", () => {
    const deniedCases: Array<[string, string]> = [
      ["::1", "loopback"],
      ["::", "unspecified"],
      ["::ffff:127.0.0.1", "v4-mapped loopback (dotted)"],
      ["::ffff:169.254.169.254", "v4-mapped AWS metadata (dotted)"],
      // Hex / fully-expanded IPv4-mapped forms -- must not be bypassed.
      ["::ffff:7f00:1", "v4-mapped loopback (hex)"],
      ["::ffff:7F00:0001", "v4-mapped loopback (hex uppercase)"],
      ["::ffff:a9fe:a9fe", "v4-mapped AWS metadata (hex)"],
      ["0:0:0:0:0:ffff:7f00:1", "v4-mapped loopback (expanded)"],
      ["0:0:0:0:0:ffff:a9fe:a9fe", "v4-mapped metadata (expanded)"],
      ["0:0:0:0:0:ffff:127.0.0.1", "v4-mapped loopback (mixed expanded)"],
      ["::ffff:c0a8:1", "v4-mapped 192.168.0.1 (hex)"],
      ["::ffff:ac10:1", "v4-mapped 172.16.0.1 (hex)"],
      // IPv4-compatible (deprecated ::/96) -- defence in depth.
      ["::7f00:1", "v4-compatible loopback (hex)"],
      ["fe80::1", "link-local"],
      ["fc00::1", "unique local"],
      ["fd12::1", "unique local"],
      ["ff00::1", "multicast"],
      ["fec0::1", "site-local"],
    ]
    for (const [ip, description] of deniedCases) {
      test(`${ip} (${description}) is denied`, () => {
        expect(isDeniedIp(ip)).toBe(true)
      })
    }
  })

  describe("IPv6 public addresses are allowed", () => {
    const allowedCases = [
      "2001:4860:4860::8888",
      "2606:4700:4700::1111",
      "::ffff:1.1.1.1",
      // Abbreviated forms that LOOK like fe80::/10 or fc00::/7 but aren't
      // once fully expanded. The previous regex-based check false-positively
      // denied these because /^fe[89ab][0-9a-f]?:/ and
      // /^f[cd][0-9a-f]{0,2}:/ admitted missing trailing hex digits.
      "fe8::1", // 0fe8::1, NOT link-local (fe80::/10)
      "fc::1", // 00fc::1, NOT unique-local (fc00::/7)
      "fec::1", // 0fec::1, NOT site-local (fec0::/10)
    ]
    for (const ip of allowedCases) {
      test(`${ip} is allowed`, () => {
        expect(isDeniedIp(ip)).toBe(false)
      })
    }
  })

  test("hostnames and garbage input are treated as non-literal (returns false)", () => {
    // isDeniedIp only classifies literals; DNS-resolved hostnames are
    // handled by the caller via dns.lookup + recheck.
    expect(isDeniedIp("example.com")).toBe(false)
    expect(isDeniedIp("not-an-ip")).toBe(false)
    expect(isDeniedIp("")).toBe(false)
  })
})
