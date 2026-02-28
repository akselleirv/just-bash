/**
 * Network module
 *
 * Provides secure network access with URL allow-list enforcement.
 */

export {
  createSecureFetchManager,
  type SecureFetch,
  SecureFetchManager,
  type SecureFetchOptions,
} from "./fetch.js";

export {
  type FetchResult,
  type HttpMethod,
  NetworkAccessDeniedError,
  type NetworkConfig,
  RedirectNotAllowedError,
  TooManyRedirectsError,
} from "./types.js";
