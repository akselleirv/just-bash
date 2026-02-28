import { describe, expect, it } from "vitest";
import { Sandbox } from "../sandbox/Sandbox.js";

// ======================================================================
// Sandbox with NetworkPolicy — creation
// ======================================================================

describe("Sandbox with networkPolicy", () => {
  it("rejects both network and networkPolicy", async () => {
    await expect(
      Sandbox.create({
        network: { allowedDomains: ["example.com"] },
        networkPolicy: "allow-all",
      }),
    ).rejects.toThrow("Cannot specify both");
  });

  it("deny-all blocks all requests", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: "deny-all",
    });

    const cmd = await sandbox.runCommand("curl https://any-domain.com/test");
    const stderr = await cmd.stderr();
    expect(stderr).toContain("Network access denied");
  });

  it("allow-all permits any domain", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: "allow-all",
    });

    const cmd = await sandbox.runCommand("curl https://any-domain.com/test");
    const stderr = await cmd.stderr();
    expect(stderr).not.toContain("Network access denied");
  });

  it("domain list allows listed domains and blocks others", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: {
        allow: ["api.example.com"],
      },
    });

    const allowed = await sandbox.runCommand(
      "curl https://api.example.com/test",
    );
    const allowedStderr = await allowed.stderr();
    expect(allowedStderr).not.toContain("Network access denied");

    const blocked = await sandbox.runCommand(
      "curl https://other-domain.com/test",
    );
    const blockedStderr = await blocked.stderr();
    expect(blockedStderr).toContain("Network access denied");
  });

  it("wildcard domains match subdomains", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: {
        allow: ["*.example.com"],
      },
    });

    const allowed = await sandbox.runCommand(
      "curl https://api.example.com/test",
    );
    const allowedStderr = await allowed.stderr();
    expect(allowedStderr).not.toContain("Network access denied");

    const blocked = await sandbox.runCommand(
      "curl https://other-domain.com/test",
    );
    const blockedStderr = await blocked.stderr();
    expect(blockedStderr).toContain("Network access denied");
  });

  it("record-style allow with wildcard '*' permits any domain", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: {
        allow: { "*": [] },
      },
    });

    const cmd = await sandbox.runCommand("curl https://any-domain.com/test");
    const stderr = await cmd.stderr();
    expect(stderr).not.toContain("Network access denied");
  });

  it("empty allow object blocks all requests", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: {},
    });

    const cmd = await sandbox.runCommand("curl https://any-domain.com/test");
    const stderr = await cmd.stderr();
    expect(stderr).toContain("Network access denied");
  });
});

// ======================================================================
// Sandbox.updateNetworkPolicy() — runtime policy changes
// ======================================================================

describe("Sandbox.updateNetworkPolicy()", () => {
  it("switching to deny-all blocks previously allowed requests", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: "allow-all",
    });

    sandbox.updateNetworkPolicy("deny-all");

    const cmd = await sandbox.runCommand("curl https://any-domain.com/test");
    const stderr = await cmd.stderr();
    expect(stderr).toContain("Network access denied");
  });

  it("switching from deny-all to domain list unblocks matching domains", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: "deny-all",
    });

    sandbox.updateNetworkPolicy({
      allow: ["api.example.com"],
    });

    const allowed = await sandbox.runCommand(
      "curl https://api.example.com/test",
    );
    const allowedStderr = await allowed.stderr();
    expect(allowedStderr).not.toContain("Network access denied");

    const blocked = await sandbox.runCommand(
      "curl https://other-domain.com/test",
    );
    const blockedStderr = await blocked.stderr();
    expect(blockedStderr).toContain("Network access denied");
  });

  it("enables network commands when called without initial config", async () => {
    const sandbox = await Sandbox.create();

    const cmd1 = await sandbox.runCommand("curl --help");
    const stderr1 = await cmd1.stderr();
    expect(stderr1).toContain("not found");

    sandbox.updateNetworkPolicy("allow-all");

    const cmd2 = await sandbox.runCommand("curl --help");
    const stdout2 = await cmd2.stdout();
    expect(stdout2).toContain("curl");
  });

  it("lifecycle: allow-all → deny-all → specific domain → deny-all", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: "allow-all",
    });

    // Phase 1: allow-all permits anything
    const cmd1 = await sandbox.runCommand("curl https://random.com/test");
    const stderr1 = await cmd1.stderr();
    expect(stderr1).not.toContain("Network access denied");

    // Phase 2: deny-all blocks everything
    sandbox.updateNetworkPolicy("deny-all");
    const cmd2 = await sandbox.runCommand("curl https://random.com/test");
    const stderr2 = await cmd2.stderr();
    expect(stderr2).toContain("Network access denied");

    // Phase 3: specific domain allowed, others blocked
    sandbox.updateNetworkPolicy({
      allow: ["api.example.com"],
    });
    const cmd3 = await sandbox.runCommand("curl https://api.example.com/test");
    const stderr3 = await cmd3.stderr();
    expect(stderr3).not.toContain("Network access denied");

    const cmd4 = await sandbox.runCommand("curl https://random.com/test");
    const stderr4 = await cmd4.stderr();
    expect(stderr4).toContain("Network access denied");

    // Phase 4: deny-all again
    sandbox.updateNetworkPolicy("deny-all");
    const cmd5 = await sandbox.runCommand("curl https://api.example.com/test");
    const stderr5 = await cmd5.stderr();
    expect(stderr5).toContain("Network access denied");
  });

  it("throws if signal is already aborted", async () => {
    const sandbox = await Sandbox.create({
      networkPolicy: "allow-all",
    });

    const controller = new AbortController();
    controller.abort();
    expect(() =>
      sandbox.updateNetworkPolicy("deny-all", {
        signal: controller.signal,
      }),
    ).toThrow();
  });
});
