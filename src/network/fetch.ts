/**
 * Secure fetch wrapper with allow-list enforcement
 *
 * This module provides a fetch wrapper that:
 * 1. Enforces URL allow-list at the fetch layer (not subject to parsing)
 * 2. Handles redirects manually to check each redirect target against the allow-list
 * 3. Provides timeout support
 */

import {
  isDomainAllowed,
  isUrlAllowed,
  matchesDomainEntry,
} from "./allow-list.js";
import type { ResolvedTransformRule } from "./network-policy.js";
import {
  type FetchResult,
  type HttpMethod,
  MethodNotAllowedError,
  NetworkAccessDeniedError,
  type NetworkConfig,
  RedirectNotAllowedError,
  ResponseTooLargeError,
  TooManyRedirectsError,
} from "./types.js";

const DEFAULT_MAX_REDIRECTS = 20;
const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_MAX_RESPONSE_SIZE = 10485760; // 10MB
const DEFAULT_ALLOWED_METHODS: HttpMethod[] = ["GET", "HEAD"];

/**
 * HTTP methods that should not have a body
 */
const BODYLESS_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * Redirect status codes
 */
const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

export interface SecureFetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  followRedirects?: boolean;
  /** Override timeout for this request (capped at global timeout) */
  timeoutMs?: number;
}

/**
 * Type for the secure fetch function
 */
export type SecureFetch = (
  url: string,
  options?: SecureFetchOptions,
) => Promise<FetchResult>;

/**
 * Manages a secure fetch function with updatable network policy.
 * Allows dynamic updates to the network configuration without recreating the fetch function.
 */
export class SecureFetchManager {
  private config: NetworkConfig;
  private transformRules: ResolvedTransformRule[] = [];

  constructor(config: NetworkConfig) {
    this.config = config;
  }

  /**
   * Updates the network configuration.
   * Takes effect immediately for subsequent fetch calls.
   */
  updateConfig(config: NetworkConfig): void {
    this.config = config;
  }

  /**
   * Returns the current network configuration.
   */
  getConfig(): NetworkConfig {
    return this.config;
  }

  /**
   * Sets per-domain header injection rules (credentials brokering).
   * Headers are injected at the fetch layer — secrets never enter the sandbox scope.
   */
  setTransformRules(rules: ResolvedTransformRule[]): void {
    this.transformRules = rules;
  }

  /**
   * Returns the current transform rules.
   */
  getTransformRules(): ResolvedTransformRule[] {
    return this.transformRules;
  }

  private getEffectiveAllowedMethods(): string[] {
    return this.config.dangerouslyAllowFullInternetAccess
      ? ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
      : (this.config.allowedMethods ?? DEFAULT_ALLOWED_METHODS);
  }

  /**
   * Checks if a URL is allowed by the current configuration.
   * A URL is allowed if it matches either allowedUrlPrefixes OR allowedDomains.
   */
  private checkAllowed(url: string): void {
    if (this.config.dangerouslyAllowFullInternetAccess) {
      return;
    }

    if (isUrlAllowed(url, this.config.allowedUrlPrefixes ?? [])) {
      return;
    }

    if (isDomainAllowed(url, this.config.allowedDomains ?? [])) {
      return;
    }

    throw new NetworkAccessDeniedError(url);
  }

  /**
   * Checks if an HTTP method is allowed by the current configuration.
   */
  private checkMethodAllowed(method: string): void {
    if (this.config.dangerouslyAllowFullInternetAccess) {
      return;
    }

    const upperMethod = method.toUpperCase();
    const allowedMethods = this.getEffectiveAllowedMethods();
    if (!allowedMethods.includes(upperMethod)) {
      throw new MethodNotAllowedError(upperMethod, allowedMethods);
    }
  }

  /**
   * Checks if a redirect URL is allowed by the current configuration.
   */
  private checkRedirectAllowed(redirectUrl: string): void {
    if (this.config.dangerouslyAllowFullInternetAccess) {
      return;
    }

    const urlAllowed = isUrlAllowed(
      redirectUrl,
      this.config.allowedUrlPrefixes ?? [],
    );
    const domainAllowed = isDomainAllowed(
      redirectUrl,
      this.config.allowedDomains ?? [],
    );
    if (!urlAllowed && !domainAllowed) {
      throw new RedirectNotAllowedError(redirectUrl);
    }
  }

  /**
   * Resolves headers to inject for a given URL based on transform rules.
   * Matches domain patterns (including wildcards) and merges all matching headers.
   * Later rules override earlier ones for the same header name.
   */
  private resolveTransformHeaders(url: string): Record<string, string> | null {
    if (this.transformRules.length === 0) {
      return null;
    }

    let hostname: string;
    try {
      hostname = new URL(url).hostname.toLowerCase();
    } catch {
      return null;
    }

    const merged: Record<string, string> = Object.create(null);
    let hasHeaders = false;

    for (const rule of this.transformRules) {
      // "*" matches all domains
      const matches =
        rule.domain === "*" || matchesDomainEntry(hostname, rule.domain);
      if (matches) {
        for (const [key, value] of Object.entries(rule.headers)) {
          merged[key] = value;
          hasHeaders = true;
        }
      }
    }

    return hasHeaders ? merged : null;
  }

  /**
   * Creates the secure fetch function bound to this manager.
   */
  createFetch(): SecureFetch {
    return (url: string, options?: SecureFetchOptions) =>
      this.fetch(url, options);
  }

  private async fetch(
    url: string,
    options: SecureFetchOptions = {},
  ): Promise<FetchResult> {
    const method = options.method?.toUpperCase() ?? "GET";
    const maxRedirects = this.config.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
    const timeoutMs = this.config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxResponseSize =
      this.config.maxResponseSize ?? DEFAULT_MAX_RESPONSE_SIZE;

    // Check if URL and method are allowed
    this.checkAllowed(url);
    this.checkMethodAllowed(method);

    let currentUrl = url;
    let redirectCount = 0;
    const followRedirects = options.followRedirects ?? true;

    const effectiveTimeout =
      options.timeoutMs !== undefined
        ? Math.min(options.timeoutMs, timeoutMs)
        : timeoutMs;

    while (true) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), effectiveTimeout);

      try {
        // Merge user headers with injected transform headers.
        // Transform headers are applied AFTER user headers, so they always win.
        // This prevents sandbox code from overriding brokered credentials.
        let mergedHeaders: Record<string, string> | undefined = options.headers;
        const transformHeaders = this.resolveTransformHeaders(currentUrl);
        if (transformHeaders) {
          mergedHeaders = {
            ...(options.headers ?? {}),
            ...transformHeaders,
          };
        }

        const fetchOptions: RequestInit = {
          method,
          headers: mergedHeaders,
          signal: controller.signal,
          redirect: "manual",
        };

        if (options.body && !BODYLESS_METHODS.has(method)) {
          fetchOptions.body = options.body;
        }

        const response = await fetch(currentUrl, fetchOptions);

        if (REDIRECT_CODES.has(response.status) && followRedirects) {
          const location = response.headers.get("location");
          if (!location) {
            return await responseToResult(
              response,
              currentUrl,
              maxResponseSize,
            );
          }

          const redirectUrl = new URL(location, currentUrl).href;
          this.checkRedirectAllowed(redirectUrl);

          redirectCount++;
          if (redirectCount > maxRedirects) {
            throw new TooManyRedirectsError(maxRedirects);
          }

          currentUrl = redirectUrl;
          continue;
        }

        return await responseToResult(response, currentUrl, maxResponseSize);
      } finally {
        clearTimeout(timeoutId);
      }
    }
  }
}

/**
 * Creates a SecureFetchManager for dynamic network policy management.
 * Use this when you need to update network policies at runtime.
 */
export function createSecureFetchManager(
  config: NetworkConfig,
): SecureFetchManager {
  return new SecureFetchManager(config);
}

/**
 * Converts a Response to a FetchResult, enforcing response size limits.
 */
async function responseToResult(
  response: Response,
  url: string,
  maxResponseSize: number,
): Promise<FetchResult> {
  // Use null-prototype to prevent prototype pollution via malicious response headers
  const headers: Record<string, string> = Object.create(null);
  response.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  // Fast path: check Content-Length header
  if (maxResponseSize > 0) {
    const contentLength = response.headers.get("content-length");
    if (contentLength) {
      const size = parseInt(contentLength, 10);
      if (!Number.isNaN(size) && size > maxResponseSize) {
        throw new ResponseTooLargeError(maxResponseSize);
      }
    }
  }

  // Read body with size tracking
  let body: string;
  if (maxResponseSize > 0 && response.body) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const chunks: string[] = [];
    let totalSize = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalSize += value.byteLength;
      if (totalSize > maxResponseSize) {
        reader.cancel();
        throw new ResponseTooLargeError(maxResponseSize);
      }
      chunks.push(decoder.decode(value, { stream: true }));
    }
    chunks.push(decoder.decode());
    body = chunks.join("");
  } else {
    body = await response.text();
  }

  return {
    status: response.status,
    statusText: response.statusText,
    headers,
    body,
    url,
  };
}
