/**
 * URL allow-list matching
 *
 * This module provides URL allow-list matching that is enforced at the fetch layer,
 * independent of any parsing or user input manipulation.
 */

/**
 * Parses a URL string into its components.
 * Returns null if the URL is invalid.
 */
export function parseUrl(
  urlString: string,
): { origin: string; pathname: string; href: string } | null {
  try {
    const url = new URL(urlString);
    return {
      origin: url.origin,
      pathname: url.pathname,
      href: url.href,
    };
  } catch {
    return null;
  }
}

/**
 * Normalizes an allow-list entry for consistent matching.
 * - Removes trailing slashes from origins without paths
 * - Preserves path prefixes as-is
 */
export function normalizeAllowListEntry(entry: string): {
  origin: string;
  pathPrefix: string;
} | null {
  const parsed = parseUrl(entry);
  if (!parsed) {
    return null;
  }

  return {
    origin: parsed.origin,
    // Keep the pathname exactly as specified (including trailing slash if present)
    pathPrefix: parsed.pathname,
  };
}

/**
 * Checks if a URL matches an allow-list entry.
 *
 * The matching rules are:
 * 1. Origins must match exactly (case-sensitive for scheme and host)
 * 2. The URL's path must start with the allow-list entry's path
 * 3. If the allow-list entry has no path (or just "/"), all paths are allowed
 *
 * @param url The URL to check (as a string)
 * @param allowedEntry The allow-list entry to match against
 * @returns true if the URL matches the allow-list entry
 */
export function matchesAllowListEntry(
  url: string,
  allowedEntry: string,
): boolean {
  const parsedUrl = parseUrl(url);
  if (!parsedUrl) {
    return false;
  }

  const normalizedEntry = normalizeAllowListEntry(allowedEntry);
  if (!normalizedEntry) {
    return false;
  }

  // Origins must match exactly
  if (parsedUrl.origin !== normalizedEntry.origin) {
    return false;
  }

  // If the allow-list entry is just the origin (path is "/" or empty), allow all paths
  if (normalizedEntry.pathPrefix === "/" || normalizedEntry.pathPrefix === "") {
    return true;
  }

  // The URL's path must start with the allow-list entry's path prefix
  return parsedUrl.pathname.startsWith(normalizedEntry.pathPrefix);
}

/**
 * Checks if a URL is allowed by any entry in the allow-list.
 *
 * @param url The URL to check
 * @param allowedUrlPrefixes The list of allowed URL prefixes
 * @returns true if the URL is allowed
 */
export function isUrlAllowed(
  url: string,
  allowedUrlPrefixes: string[],
): boolean {
  if (!allowedUrlPrefixes || allowedUrlPrefixes.length === 0) {
    return false;
  }

  return allowedUrlPrefixes.some((entry) => matchesAllowListEntry(url, entry));
}

/**
 * Checks if a hostname matches an allowed domain entry.
 *
 * Matching rules:
 * - "example.com" matches only "example.com" (exact match)
 * - "*.example.com" matches any subdomain like "api.example.com", "www.example.com"
 *   but NOT "example.com" itself
 *
 * @param hostname The hostname to check (lowercase, no port)
 * @param domainEntry The domain entry to match against
 */
export function matchesDomainEntry(
  hostname: string,
  domainEntry: string,
): boolean {
  const host = hostname.toLowerCase();
  const entry = domainEntry.toLowerCase();

  if (entry.startsWith("*.")) {
    // Wildcard: *.example.com matches sub.example.com but not example.com
    const parentDomain = entry.slice(2); // Remove "*."
    if (!parentDomain || parentDomain.includes("*")) {
      return false; // Invalid: empty parent or nested wildcards
    }
    // hostname must end with .parentDomain and have at least one character before it
    return (
      host.endsWith(`.${parentDomain}`) && host.length > parentDomain.length + 1
    );
  }

  if (entry.includes("*")) {
    return false; // Wildcards only valid at the start as *. prefix
  }

  // Exact match
  return host === entry;
}

/**
 * Checks if a URL's hostname is allowed by any entry in the domain list.
 *
 * @param url The URL to check
 * @param allowedDomains The list of allowed domains (supports wildcards)
 * @returns true if the URL's hostname is allowed
 */
export function isDomainAllowed(
  url: string,
  allowedDomains: string[],
): boolean {
  if (!allowedDomains || allowedDomains.length === 0) {
    return false;
  }

  const parsed = parseUrl(url);
  if (!parsed) {
    return false;
  }

  // Extract hostname from the origin
  let hostname: string;
  try {
    hostname = new URL(parsed.href).hostname.toLowerCase();
  } catch {
    return false;
  }

  return allowedDomains.some((entry) => matchesDomainEntry(hostname, entry));
}

/**
 * Validates a domain allow-list configuration.
 * Returns an array of error messages for invalid entries.
 */
export function validateDomainAllowList(allowedDomains: string[]): string[] {
  const errors: string[] = [];

  for (const entry of allowedDomains) {
    if (!entry || entry.trim() === "") {
      errors.push("Empty domain in allow-list");
      continue;
    }

    const domain = entry.startsWith("*.") ? entry.slice(2) : entry;

    if (!domain) {
      errors.push(`Invalid wildcard domain: "${entry}" - nothing after *.`);
      continue;
    }

    // Check for nested wildcards
    if (domain.includes("*")) {
      errors.push(
        `Invalid domain in allow-list: "${entry}" - wildcards only supported as *. prefix`,
      );
      continue;
    }

    // Check for schemes (domains should be hostnames, not URLs)
    if (domain.includes("://")) {
      errors.push(
        `Invalid domain in allow-list: "${entry}" - use hostname only, not a URL`,
      );
      continue;
    }

    // Check for paths
    if (domain.includes("/")) {
      errors.push(
        `Invalid domain in allow-list: "${entry}" - use hostname only, no paths (use allowedUrlPrefixes for path filtering)`,
      );
    }
  }

  return errors;
}

/**
 * Validates an allow-list configuration.
 * Each entry must be a full origin (scheme + host), optionally followed by a path prefix.
 * Returns an array of error messages for invalid entries.
 */
export function validateAllowList(allowedUrlPrefixes: string[]): string[] {
  const errors: string[] = [];

  for (const entry of allowedUrlPrefixes) {
    const parsed = parseUrl(entry);
    if (!parsed) {
      errors.push(
        `Invalid URL in allow-list: "${entry}" - must be a valid URL with scheme and host (e.g., "https://example.com")`,
      );
      continue;
    }

    const url = new URL(entry);

    // Only allow http and https
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      errors.push(
        `Only http and https URLs are allowed in allow-list: "${entry}"`,
      );
      continue;
    }

    // Must have a valid host (not empty)
    if (!url.hostname) {
      errors.push(`Allow-list entry must include a hostname: "${entry}"`);
      continue;
    }

    // Warn about query strings and fragments (they'll be ignored)
    if (url.search || url.hash) {
      errors.push(
        `Query strings and fragments are ignored in allow-list entries: "${entry}"`,
      );
    }
  }

  return errors;
}
