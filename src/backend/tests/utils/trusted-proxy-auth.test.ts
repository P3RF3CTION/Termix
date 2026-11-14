import { describe, expect, it } from "vitest";
import {
  getTrustedProxyAuthConfig,
  getTrustedProxySourceAddress,
  isTrustedProxyAddress,
  parseTrustedProxyRoleMap,
  resolveTrustedProxyRoles,
} from "../../utils/trusted-proxy-auth.js";

describe("trusted proxy authentication config", () => {
  it("requires an explicit proxy allowlist and role map", () => {
    expect(() =>
      getTrustedProxyAuthConfig({ TRUSTED_PROXY_AUTH_ENABLED: "true" }),
    ).toThrow(/requires/);
    expect(() =>
      getTrustedProxyAuthConfig({
        TRUSTED_PROXY_AUTH_ENABLED: "true",
        TRUSTED_PROXY_AUTH_TRUSTED_PROXIES: "not-a-cidr",
        TRUSTED_PROXY_AUTH_ROLE_MAP: '{"operators":"user"}',
      }),
    ).toThrow(/Invalid trusted proxy/);
  });

  it("matches exact addresses, CIDRs, and IPv4-mapped addresses", () => {
    const trusted = ["10.20.0.0/16", "2001:db8::/32"];
    expect(isTrustedProxyAddress("10.20.1.4", trusted)).toBe(true);
    expect(isTrustedProxyAddress("::ffff:10.20.1.4", trusted)).toBe(true);
    expect(isTrustedProxyAddress("10.21.1.4", trusted)).toBe(false);
    expect(isTrustedProxyAddress("2001:db8::5", trusted)).toBe(true);
  });

  it("judges requests relayed by the bundled nginx by nginx's own peer", () => {
    const viaNginx = (peer?: string) => ({
      headers: peer ? { "x-termix-proxy-peer": peer } : {},
      socket: { remoteAddress: "::ffff:127.0.0.1" },
    });
    expect(getTrustedProxySourceAddress(viaNginx("172.20.0.10"))).toBe(
      "172.20.0.10",
    );
    // A client reaching nginx directly is reported as itself, so trusting
    // the auth proxy no longer means trusting nginx on loopback.
    expect(
      isTrustedProxyAddress(
        getTrustedProxySourceAddress(viaNginx("203.0.113.7")),
        ["127.0.0.1"],
      ),
    ).toBe(false);
    // A local reverse proxy that does not set the header keeps working.
    expect(getTrustedProxySourceAddress(viaNginx())).toBe("::ffff:127.0.0.1");
  });

  it("ignores the peer header on connections that are not from loopback", () => {
    expect(
      getTrustedProxySourceAddress({
        headers: { "x-termix-proxy-peer": "172.20.0.10" },
        socket: { remoteAddress: "198.51.100.9" },
      }),
    ).toBe("198.51.100.9");
  });

  it("rejects a peer secret whose UTF-8 bytes do not match without throwing", () => {
    process.env.TERMIX_TRUSTED_PROXY_PEER_SECRET = "abcd"; // 4 bytes
    try {
      // Four characters, eight UTF-8 bytes — timingSafeEqual needs equal
      // byte lengths and would throw RangeError if the string char count
      // were taken as the length to compare. The source address must then
      // fall back to the socket, not 500 the request.
      expect(
        getTrustedProxySourceAddress({
          headers: {
            "x-termix-proxy-peer": "172.20.0.10",
            "x-termix-proxy-secret": "éééé",
          },
          socket: { remoteAddress: "::ffff:127.0.0.1" },
        }),
      ).toBe("::ffff:127.0.0.1");
    } finally {
      delete process.env.TERMIX_TRUSTED_PROXY_PEER_SECRET;
    }
  });

  it("honours a matching peer secret while rejecting a wrong one", () => {
    process.env.TERMIX_TRUSTED_PROXY_PEER_SECRET = "s3cret";
    try {
      expect(
        getTrustedProxySourceAddress({
          headers: {
            "x-termix-proxy-peer": "172.20.0.10",
            "x-termix-proxy-secret": "s3cret",
          },
          socket: { remoteAddress: "::ffff:127.0.0.1" },
        }),
      ).toBe("172.20.0.10");
      expect(
        getTrustedProxySourceAddress({
          headers: {
            "x-termix-proxy-peer": "172.20.0.10",
            "x-termix-proxy-secret": "wrong!",
          },
          socket: { remoteAddress: "::ffff:127.0.0.1" },
        }),
      ).toBe("::ffff:127.0.0.1");
    } finally {
      delete process.env.TERMIX_TRUSTED_PROXY_PEER_SECRET;
    }
  });

  it("fails closed when a supplied external role is not mapped", () => {
    const roleMap = parseTrustedProxyRoleMap(
      JSON.stringify({ operators: ["operator"], viewers: "readonly" }),
    );
    expect(resolveTrustedProxyRoles("operators, viewers", roleMap)).toEqual([
      "operator",
      "readonly",
    ]);
    expect(resolveTrustedProxyRoles("operators, admins", roleMap)).toBeNull();
  });
});
