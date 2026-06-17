// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

/** Base error for any non-2xx response from a Relix-Q API. */
export class RelixQApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  readonly path: string;

  constructor(message: string, status: number, path: string, body?: unknown) {
    super(message);
    this.name = 'RelixQApiError';
    this.status = status;
    this.path = path;
    this.body = body;
    // Restore prototype chain when compiled to ES5/CJS targets.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** 401/403 — the request needs (re)authentication. */
export class AuthenticationRequiredError extends RelixQApiError {
  constructor(path: string, status = 401, body?: unknown) {
    super(`Authentication required for ${path}`, status, path, body);
    this.name = 'AuthenticationRequiredError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** 429 — rate limited. Carries the Retry-After hint in seconds when present. */
export class RateLimitedError extends RelixQApiError {
  readonly retryAfterSeconds: number | null;

  constructor(path: string, retryAfterSeconds: number | null, body?: unknown) {
    super(`Rate limited on ${path}`, 429, path, body);
    this.name = 'RateLimitedError';
    this.retryAfterSeconds = retryAfterSeconds;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown when a successful response body fails zod validation. */
export class ResponseValidationError extends Error {
  readonly path: string;
  readonly issues: unknown;

  constructor(path: string, issues: unknown) {
    super(`Response from ${path} did not match the expected schema`);
    this.name = 'ResponseValidationError';
    this.path = path;
    this.issues = issues;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
