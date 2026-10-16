import { describe, expect, it, vi } from "vitest";

vi.mock("dns/promises", () => ({
  default: {
    lookup: vi.fn(async (host: string) =>
      host === "mixed.example"
        ? [
            { address: "93.184.216.34", family: 4 },
            { address: "127.0.0.1", family: 4 },
          ]
        : [{ address: "93.184.216.34", family: 4 }],
    ),
  },
}));

import { testProxyConnectivity } from "../../utils/proxy-helper.js";

describe("proxy target validation", () => {
  it("refuses a name that also resolves to a blocked address", async () => {
    await expect(
      testProxyConnectivity({
        testTarget: { host: "mixed.example", port: 22 },
      }),
    ).rejects.toThrow(/not allowed/i);
  });
});
