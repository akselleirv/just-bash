import type { NetworkConfig } from "./types.js";

/**
 * Network policy types — Vercel Sandbox-compatible interface.
 *
 * Provides domain-based access control with optional per-domain header injection
 * (credentials brokering), matching the @vercel/sandbox NetworkPolicy API.
 */

/**
 * A transform applied to network requests matching a domain rule.
 * Used for credentials brokering — injecting headers outside the sandbox scope.
 *
 * @example
 * { headers: { Authorization: "Bearer sk-..." } }
 */
export type NetworkTransformer = {
  /** Headers to set on the outgoing request. */
  headers?: Record<string, string>;
};

/**
 * A rule applied to requests matching a domain in the network policy.
 */
export type NetworkPolicyRule = {
  /** Transforms to apply to matching requests. */
  transform?: NetworkTransformer[];
};

/**
 * Network policy to define network restrictions for the sandbox.
 *
 * - `"allow-all"`: Full internet access (default when network is enabled). All traffic is allowed.
 * - `"deny-all"`: No internet access. All traffic is denied.
 * - Object: Custom access with explicit allow lists and optional per-domain transforms.
 *
 * @example
 * ```ts
 * // Allow all traffic
 * const policy: NetworkPolicy = "allow-all";
 *
 * // Deny all traffic
 * const policy: NetworkPolicy = "deny-all";
 *
 * // Allow specific domains with credentials brokering
 * const policy: NetworkPolicy = {
 *   allow: {
 *     "ai-gateway.vercel.sh": [{
 *       transform: [{ headers: { Authorization: `Bearer ${token}` } }],
 *     }],
 *     "*.github.com": [{
 *       transform: [{ headers: { Authorization: `Bearer ${ghToken}` } }],
 *     }],
 *     "*": [], // Allow all other domains without transforms
 *   },
 * };
 *
 * // Simple domain list (no transforms)
 * const policy: NetworkPolicy = {
 *   allow: ["api.example.com", "*.cdn.example.com"],
 * };
 * ```
 */
export type NetworkPolicy =
  | "allow-all"
  | "deny-all"
  | {
      /**
       * Domains to allow traffic to.
       *
       * Can be:
       * - `string[]`: Simple list of allowed domains (supports `*.` wildcard prefix)
       * - `Record<string, NetworkPolicyRule[]>`: Domain-keyed rules with optional transforms.
       *   Use `"*"` as a key to allow all domains not explicitly listed.
       */
      allow?: string[] | Record<string, NetworkPolicyRule[]>;
    };

/**
 * Resolved transform rule: a domain pattern mapped to headers to inject.
 */
export interface ResolvedTransformRule {
  domain: string;
  headers: Record<string, string>;
}

/**
 * Resolved network policy, broken into components for the fetch layer.
 */
export interface ResolvedNetworkPolicy {
  /** Whether all internet access is allowed */
  allowAll: boolean;
  /** Whether all internet access is denied */
  denyAll: boolean;
  /** Allowed domains (for domain-based filtering) */
  allowedDomains: string[];
  /** Per-domain header injection rules */
  transformRules: ResolvedTransformRule[];
}

/**
 * Resolves a NetworkPolicy into its component parts for the fetch layer.
 *
 * This converts the Vercel Sandbox-compatible NetworkPolicy type into the
 * internal representation used by SecureFetchManager.
 */
export function resolveNetworkPolicy(
  policy: NetworkPolicy,
): ResolvedNetworkPolicy {
  if (policy === "allow-all") {
    return {
      allowAll: true,
      denyAll: false,
      allowedDomains: [],
      transformRules: [],
    };
  }

  if (policy === "deny-all") {
    return {
      allowAll: false,
      denyAll: true,
      allowedDomains: [],
      transformRules: [],
    };
  }

  const result: ResolvedNetworkPolicy = {
    allowAll: false,
    denyAll: false,
    allowedDomains: [],
    transformRules: [],
  };

  if (!policy.allow) {
    // No allow rules = deny all
    result.denyAll = true;
    return result;
  }

  if (Array.isArray(policy.allow)) {
    // Simple domain list
    result.allowedDomains = policy.allow;
    return result;
  }

  // Record<string, NetworkPolicyRule[]> form
  for (const [domain, rules] of Object.entries(policy.allow)) {
    if (domain === "*") {
      // Wildcard: allow all domains
      result.allowAll = true;
    } else {
      result.allowedDomains.push(domain);
    }

    // Extract transform rules
    for (const rule of rules) {
      if (rule.transform) {
        for (const transform of rule.transform) {
          if (transform.headers && Object.keys(transform.headers).length > 0) {
            result.transformRules.push({
              domain,
              headers: transform.headers,
            });
          }
        }
      }
    }
  }

  return result;
}

/**
 * Converts a NetworkPolicy to the internal NetworkConfig used by the fetch layer.
 *
 * Transform rules (credentials brokering) are NOT included in the returned config —
 * they must be applied separately via `SecureFetchManager.setTransformRules()`.
 */
export function networkPolicyToConfig(policy: NetworkPolicy): NetworkConfig {
  if (policy === "allow-all") {
    return {
      dangerouslyAllowFullInternetAccess: true,
    };
  }

  if (policy === "deny-all") {
    // Empty allow lists = nothing is allowed
    return {
      allowedDomains: [],
      allowedUrlPrefixes: [],
    };
  }

  const resolved = resolveNetworkPolicy(policy);

  if (resolved.allowAll) {
    return {
      dangerouslyAllowFullInternetAccess: true,
    };
  }

  if (resolved.denyAll) {
    return {
      allowedDomains: [],
      allowedUrlPrefixes: [],
    };
  }

  return {
    allowedDomains: resolved.allowedDomains,
  };
}
