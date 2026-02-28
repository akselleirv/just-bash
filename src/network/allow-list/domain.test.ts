import { describe, expect, it } from "vitest";
import {
  isDomainAllowed,
  matchesDomainEntry,
  validateDomainAllowList,
} from "../allow-list.js";

describe("matchesDomainEntry", () => {
  describe("exact match", () => {
    it("matches exact domain", () => {
      expect(matchesDomainEntry("example.com", "example.com")).toBe(true);
    });

    it("is case-insensitive", () => {
      expect(matchesDomainEntry("example.com", "Example.COM")).toBe(true);
      expect(matchesDomainEntry("Example.COM", "example.com")).toBe(true);
    });

    it("does not match subdomain", () => {
      expect(matchesDomainEntry("api.example.com", "example.com")).toBe(false);
    });

    it("does not match different domain", () => {
      expect(matchesDomainEntry("other.com", "example.com")).toBe(false);
    });

    it("does not match domain suffix", () => {
      expect(matchesDomainEntry("evilexample.com", "example.com")).toBe(false);
    });

    it("does not match domain prefix", () => {
      expect(matchesDomainEntry("example.com.evil.com", "example.com")).toBe(
        false,
      );
    });
  });

  describe("wildcard match", () => {
    it("matches subdomain", () => {
      expect(matchesDomainEntry("api.example.com", "*.example.com")).toBe(true);
    });

    it("matches www subdomain", () => {
      expect(matchesDomainEntry("www.example.com", "*.example.com")).toBe(true);
    });

    it("matches deep subdomain", () => {
      expect(matchesDomainEntry("deep.sub.example.com", "*.example.com")).toBe(
        true,
      );
    });

    it("does NOT match exact domain (wildcard requires at least one level)", () => {
      expect(matchesDomainEntry("example.com", "*.example.com")).toBe(false);
    });

    it("is case-insensitive", () => {
      expect(matchesDomainEntry("API.Example.COM", "*.example.com")).toBe(true);
    });

    it("does not match different domain", () => {
      expect(matchesDomainEntry("api.other.com", "*.example.com")).toBe(false);
    });

    it("does not match domain suffix attacks", () => {
      expect(matchesDomainEntry("evilexample.com", "*.example.com")).toBe(
        false,
      );
    });

    it("rejects nested wildcards", () => {
      expect(matchesDomainEntry("api.example.com", "*.*.example.com")).toBe(
        false,
      );
    });

    it("rejects mid-string wildcards", () => {
      expect(matchesDomainEntry("api.example.com", "api.*.com")).toBe(false);
    });

    it("rejects empty parent domain after *.", () => {
      expect(matchesDomainEntry("anything", "*.")).toBe(false);
    });
  });
});

describe("isDomainAllowed", () => {
  it("returns false for empty domain list", () => {
    expect(isDomainAllowed("https://example.com/path", [])).toBe(false);
  });

  it("returns false for undefined domain list", () => {
    expect(
      isDomainAllowed(
        "https://example.com/path",
        undefined as unknown as string[],
      ),
    ).toBe(false);
  });

  it("allows URL when domain matches exactly", () => {
    expect(
      isDomainAllowed("https://example.com/any/path", ["example.com"]),
    ).toBe(true);
  });

  it("allows URL when domain matches wildcard", () => {
    expect(
      isDomainAllowed("https://api.example.com/v1/users", ["*.example.com"]),
    ).toBe(true);
  });

  it("allows any scheme", () => {
    expect(isDomainAllowed("http://example.com/path", ["example.com"])).toBe(
      true,
    );
    expect(isDomainAllowed("https://example.com/path", ["example.com"])).toBe(
      true,
    );
  });

  it("allows any path", () => {
    expect(isDomainAllowed("https://example.com/", ["example.com"])).toBe(true);
    expect(
      isDomainAllowed("https://example.com/deep/nested/path", ["example.com"]),
    ).toBe(true);
  });

  it("allows any port", () => {
    expect(
      isDomainAllowed("https://example.com:8080/path", ["example.com"]),
    ).toBe(true);
    expect(
      isDomainAllowed("http://example.com:3000/api", ["example.com"]),
    ).toBe(true);
  });

  it("blocks URL when domain does not match", () => {
    expect(isDomainAllowed("https://other.com/path", ["example.com"])).toBe(
      false,
    );
  });

  it("returns false for invalid URL", () => {
    expect(isDomainAllowed("not-a-url", ["example.com"])).toBe(false);
  });

  it("handles multiple domain entries", () => {
    const domains = ["api.example.com", "*.cdn.example.com"];
    expect(isDomainAllowed("https://api.example.com/v1", domains)).toBe(true);
    expect(isDomainAllowed("https://us.cdn.example.com/assets", domains)).toBe(
      true,
    );
    expect(isDomainAllowed("https://other.com/path", domains)).toBe(false);
  });
});

describe("validateDomainAllowList", () => {
  it("returns empty array for valid entries", () => {
    expect(
      validateDomainAllowList([
        "example.com",
        "*.example.com",
        "api.example.com",
      ]),
    ).toEqual([]);
  });

  it("rejects empty strings", () => {
    const errors = validateDomainAllowList([""]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("Empty domain");
  });

  it("rejects URLs with schemes", () => {
    const errors = validateDomainAllowList(["https://example.com"]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("hostname only, not a URL");
  });

  it("rejects entries with paths", () => {
    const errors = validateDomainAllowList(["example.com/path"]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("no paths");
  });

  it("rejects nested wildcards", () => {
    const errors = validateDomainAllowList(["*.*.example.com"]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("only supported as *. prefix");
  });

  it("rejects mid-string wildcards", () => {
    const errors = validateDomainAllowList(["api.*.com"]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("only supported as *. prefix");
  });

  it("rejects empty wildcard parent", () => {
    const errors = validateDomainAllowList(["*."]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("nothing after");
  });
});

describe("security scenarios", () => {
  it("blocks localhost unless explicitly allowed", () => {
    expect(isDomainAllowed("https://localhost/path", ["example.com"])).toBe(
      false,
    );
    expect(isDomainAllowed("https://localhost/path", ["localhost"])).toBe(true);
  });

  it("blocks IP addresses unless explicitly allowed", () => {
    expect(isDomainAllowed("https://127.0.0.1/path", ["example.com"])).toBe(
      false,
    );
    expect(isDomainAllowed("https://127.0.0.1/path", ["127.0.0.1"])).toBe(true);
  });

  it("wildcard does not match parent domain", () => {
    expect(isDomainAllowed("https://example.com/path", ["*.example.com"])).toBe(
      false,
    );
  });

  it("blocks domain suffix attacks with wildcards", () => {
    expect(
      isDomainAllowed("https://evilexample.com/path", ["*.example.com"]),
    ).toBe(false);
  });
});
