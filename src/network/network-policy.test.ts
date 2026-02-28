import { describe, expect, it } from "vitest";
import { Bash } from "../Bash.js";
import { Sandbox } from "../sandbox/Sandbox.js";
import { SecureFetchManager } from "./fetch.js";
import {
  networkPolicyToConfig,
  resolveNetworkPolicy,
} from "./network-policy.js";

// ======================================================================
// resolveNetworkPolicy()
// ======================================================================

describe("resolveNetworkPolicy()", () => {
  it("resolves 'allow-all'", () => {
    const resolved = resolveNetworkPolicy("allow-all");
    expect(resolved.allowAll).toBe(true);
    expect(resolved.denyAll).toBe(false);
    expect(resolved.allowedDomains).toEqual([]);
    expect(resolved.transformRules).toEqual([]);
  });

  it("resolves 'deny-all'", () => {
    const resolved = resolveNetworkPolicy("deny-all");
    expect(resolved.allowAll).toBe(false);
    expect(resolved.denyAll).toBe(true);
    expect(resolved.allowedDomains).toEqual([]);
    expect(resolved.transformRules).toEqual([]);
  });

  it("resolves simple domain list", () => {
    const resolved = resolveNetworkPolicy({
      allow: ["api.example.com", "*.cdn.example.com"],
    });
    expect(resolved.allowAll).toBe(false);
    expect(resolved.denyAll).toBe(false);
    expect(resolved.allowedDomains).toEqual([
      "api.example.com",
      "*.cdn.example.com",
    ]);
    expect(resolved.transformRules).toEqual([]);
  });

  it("resolves empty allow object as deny-all", () => {
    const resolved = resolveNetworkPolicy({});
    expect(resolved.denyAll).toBe(true);
  });

  it("resolves wildcard '*' as allow-all", () => {
    const resolved = resolveNetworkPolicy({
      allow: { "*": [] },
    });
    expect(resolved.allowAll).toBe(true);
  });

  it("resolves domain-keyed rules with transforms", () => {
    const resolved = resolveNetworkPolicy({
      allow: {
        "ai-gateway.vercel.sh": [
          {
            transform: [{ headers: { Authorization: "Bearer token123" } }],
          },
        ],
        "*.github.com": [
          {
            transform: [{ headers: { Authorization: "Bearer gh-token" } }],
          },
        ],
        "*": [],
      },
    });
    expect(resolved.allowAll).toBe(true);
    expect(resolved.allowedDomains).toEqual([
      "ai-gateway.vercel.sh",
      "*.github.com",
    ]);
    expect(resolved.transformRules).toHaveLength(2);
    expect(resolved.transformRules[0]).toEqual({
      domain: "ai-gateway.vercel.sh",
      headers: { Authorization: "Bearer token123" },
    });
    expect(resolved.transformRules[1]).toEqual({
      domain: "*.github.com",
      headers: { Authorization: "Bearer gh-token" },
    });
  });

  it("skips transforms with empty headers", () => {
    const resolved = resolveNetworkPolicy({
      allow: {
        "example.com": [{ transform: [{ headers: {} }] }],
      },
    });
    expect(resolved.transformRules).toEqual([]);
  });

  it("skips rules without transforms", () => {
    const resolved = resolveNetworkPolicy({
      allow: {
        "example.com": [{}],
      },
    });
    expect(resolved.transformRules).toEqual([]);
  });
});

// ======================================================================
// networkPolicyToConfig()
// ======================================================================

describe("networkPolicyToConfig()", () => {
  it("converts allow-all to dangerouslyAllowFullInternetAccess", () => {
    const config = networkPolicyToConfig("allow-all");
    expect(config.dangerouslyAllowFullInternetAccess).toBe(true);
  });

  it("converts deny-all to empty allow lists", () => {
    const config = networkPolicyToConfig("deny-all");
    expect(config.allowedDomains).toEqual([]);
    expect(config.allowedUrlPrefixes).toEqual([]);
    expect(config.dangerouslyAllowFullInternetAccess).toBeUndefined();
  });

  it("converts simple domain list", () => {
    const config = networkPolicyToConfig({
      allow: ["api.example.com", "*.cdn.example.com"],
    });
    expect(config.allowedDomains).toEqual([
      "api.example.com",
      "*.cdn.example.com",
    ]);
  });

  it("converts wildcard '*' to full access", () => {
    const config = networkPolicyToConfig({ allow: { "*": [] } });
    expect(config.dangerouslyAllowFullInternetAccess).toBe(true);
  });

  it("extracts domains from record-style allow", () => {
    const config = networkPolicyToConfig({
      allow: {
        "api.example.com": [],
        "*.github.com": [
          { transform: [{ headers: { Authorization: "Bearer x" } }] },
        ],
      },
    });
    expect(config.allowedDomains).toEqual(["api.example.com", "*.github.com"]);
  });
});

// ======================================================================
// SecureFetchManager transform rules (credentials brokering)
// ======================================================================

describe("SecureFetchManager transform rules", () => {
  it("stores and retrieves transform rules", () => {
    const manager = new SecureFetchManager({
      dangerouslyAllowFullInternetAccess: true,
    });

    manager.setTransformRules([
      { domain: "api.example.com", headers: { Authorization: "Bearer x" } },
    ]);

    expect(manager.getTransformRules()).toHaveLength(1);
    expect(manager.getTransformRules()[0].domain).toBe("api.example.com");
  });

  it("clears transform rules when set to empty", () => {
    const manager = new SecureFetchManager({
      dangerouslyAllowFullInternetAccess: true,
    });

    manager.setTransformRules([
      { domain: "api.example.com", headers: { Authorization: "Bearer x" } },
    ]);
    manager.setTransformRules([]);

    expect(manager.getTransformRules()).toHaveLength(0);
  });
});

// ======================================================================
// Bash.updateNetworkPolicy() (low-level NetworkConfig)
// ======================================================================

describe("Bash.updateNetworkPolicy()", () => {
  it("enables network access when not previously configured", async () => {
    const bash = new Bash();

    // curl should not exist before network is configured
    const result1 = await bash.exec("curl --help");
    expect(result1.exitCode).not.toBe(0);

    // Enable network with domain restriction
    bash.updateNetworkPolicy({
      allowedDomains: ["example.com"],
    });

    // curl should now exist
    const result2 = await bash.exec("curl --help");
    expect(result2.exitCode).toBe(0);
  });

  it("updates policy on existing network config", () => {
    const bash = new Bash({
      network: {
        allowedUrlPrefixes: ["https://old.example.com"],
      },
    });

    // Update to new policy
    bash.updateNetworkPolicy({
      allowedDomains: ["new.example.com"],
    });

    expect(bash).toBeDefined();
  });
});

// ======================================================================
// Sandbox with NetworkPolicy interface
// ======================================================================

describe("Sandbox with networkPolicy", () => {
  it("creates sandbox with 'allow-all' policy", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: "allow-all",
    });

    // curl should be available
    const cmd = await sandbox.runCommand("curl --help");
    const stdout = await cmd.stdout();
    expect(stdout).toContain("curl");
  });

  it("creates sandbox with 'deny-all' policy", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: "deny-all",
    });

    // curl should still be registered (network was configured, just locked down)
    const cmd = await sandbox.runCommand("curl --help");
    const stdout = await cmd.stdout();
    expect(stdout).toContain("curl");
  });

  it("creates sandbox with domain-based policy", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: {
        allow: ["api.example.com", "*.cdn.example.com"],
      },
    });

    const cmd = await sandbox.runCommand("curl --help");
    const stdout = await cmd.stdout();
    expect(stdout).toContain("curl");
  });

  it("creates sandbox with credentials brokering", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: {
        allow: {
          "ai-gateway.vercel.sh": [
            {
              transform: [
                { headers: { Authorization: "Bearer my-secret-token" } },
              ],
            },
          ],
          "*": [],
        },
      },
    });

    const cmd = await sandbox.runCommand("curl --help");
    const stdout = await cmd.stdout();
    expect(stdout).toContain("curl");
  });

  it("rejects both network and networkPolicy", async () => {
    await expect(
      Sandbox.create({
        network: { allowedDomains: ["example.com"] },
        networkPolicy: "allow-all",
      }),
    ).rejects.toThrow("Cannot specify both");
  });
});

describe("Sandbox.updateNetworkPolicy() with NetworkPolicy", () => {
  it("switches from allow-all to deny-all", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: "allow-all",
    });

    // Lock down
    sandbox.updateNetworkPolicy("deny-all");

    // curl still registered
    const cmd = await sandbox.runCommand("curl --help");
    const stdout = await cmd.stdout();
    expect(stdout).toContain("curl");
  });

  it("switches from deny-all to domain-specific with credentials", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: "deny-all",
    });

    // Open up with credentials
    sandbox.updateNetworkPolicy({
      allow: {
        "ai-gateway.vercel.sh": [
          {
            transform: [{ headers: { Authorization: "Bearer my-token" } }],
          },
        ],
      },
    });

    const cmd = await sandbox.runCommand("curl --help");
    const stdout = await cmd.stdout();
    expect(stdout).toContain("curl");
  });

  it("enables network commands after creation without initial config", async () => {
    const sandbox = await Sandbox.create();

    // curl should not exist initially
    const cmd1 = await sandbox.runCommand("curl --help");
    const stderr1 = await cmd1.stderr();
    expect(stderr1).toContain("not found");

    // Enable network via policy
    sandbox.updateNetworkPolicy("allow-all");

    // curl should now work
    const cmd2 = await sandbox.runCommand("curl --help");
    const stdout2 = await cmd2.stdout();
    expect(stdout2).toContain("curl");
  });

  it("follows Vercel Sandbox lifecycle pattern", async () => {
    // Phase 1: Full access for setup
    const sandbox = await Sandbox.create({
      networkPolicy: {
        allow: {
          "ai-gateway.vercel.sh": [
            {
              transform: [{ headers: { Authorization: "Bearer secret" } }],
            },
          ],
          "*.github.com": [
            {
              transform: [{ headers: { Authorization: "Bearer gh-token" } }],
            },
          ],
          "*": [],
        },
      },
    });

    // Phase 2: Air-gap for untrusted code
    sandbox.updateNetworkPolicy("deny-all");

    // Phase 3: Reallow specific service
    sandbox.updateNetworkPolicy({
      allow: {
        "ai-gateway.vercel.sh": [
          {
            transform: [{ headers: { Authorization: "Bearer secret" } }],
          },
        ],
      },
    });

    // Phase 4: Air-gap again
    sandbox.updateNetworkPolicy("deny-all");

    // curl should still be registered
    const cmd = await sandbox.runCommand("curl --help");
    const stdout = await cmd.stdout();
    expect(stdout).toContain("curl");
  });
});

describe("SecureFetchManager dynamic updates", () => {
  it("reflects config changes", () => {
    const manager = new SecureFetchManager({
      allowedDomains: ["allowed.com"],
    });

    const fetchFn = manager.createFetch();
    expect(typeof fetchFn).toBe("function");

    manager.updateConfig({
      allowedDomains: ["newallowed.com"],
    });

    expect(manager.getConfig().allowedDomains).toEqual(["newallowed.com"]);
  });
});
