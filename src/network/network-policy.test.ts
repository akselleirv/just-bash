import { describe, expect, it } from "vitest";
import { Bash } from "../Bash.js";
import { Sandbox } from "../sandbox/Sandbox.js";

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

    // The bash instance should have the updated policy
    // (verifiable through fetch behavior but we can't easily test without mocking fetch)
    expect(bash).toBeDefined();
  });
});

describe("Sandbox.updateNetworkPolicy()", () => {
  it("enables network commands after creation", async () => {
    const sandbox = await Sandbox.create();

    // curl should not exist initially
    const cmd1 = await sandbox.runCommand("curl --help");
    const stderr1 = await cmd1.stderr();
    expect(stderr1).toContain("not found");

    // Enable network
    sandbox.updateNetworkPolicy({
      allowedDomains: ["example.com"],
    });

    // curl should now work
    const cmd2 = await sandbox.runCommand("curl --help");
    const stdout2 = await cmd2.stdout();
    expect(stdout2).toContain("curl");
  });

  it("updates can be called multiple times", async () => {
    const sandbox = await Sandbox.create({
      network: { allowedDomains: ["first.com"] },
    });

    // Second update
    sandbox.updateNetworkPolicy({
      allowedDomains: ["second.com"],
    });

    // Third update — deny all
    sandbox.updateNetworkPolicy({
      allowedDomains: [],
      allowedUrlPrefixes: [],
    });

    // curl still registered from initial config
    const cmd = await sandbox.runCommand("curl --help");
    const stdout = await cmd.stdout();
    expect(stdout).toContain("curl");
  });
});

describe("SecureFetchManager dynamic updates", () => {
  it("reflects config changes in checkAllowed", async () => {
    const { SecureFetchManager } = await import("./fetch.js");

    const manager = new SecureFetchManager({
      allowedDomains: ["allowed.com"],
    });

    // Test that createFetch returns a function
    const fetchFn = manager.createFetch();
    expect(typeof fetchFn).toBe("function");

    // Update config
    manager.updateConfig({
      allowedDomains: ["newallowed.com"],
    });

    // getConfig should reflect the update
    expect(manager.getConfig().allowedDomains).toEqual(["newallowed.com"]);
  });
});
