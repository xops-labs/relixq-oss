// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
import type { z } from 'zod';
import {
  AuthenticationRequiredError,
  RateLimitedError,
  RelixQApiError,
  ResponseValidationError,
} from './errors';
import {
  FindingDtoSchema,
  ProjectScoreSchema,
  ScanRunSchema,
  type FindingDto,
  type ProjectScore,
  type ScanRun,
} from './schemas';

type QueryValue = string | number | boolean | undefined | null | Array<string | number>;

export interface RequestOptions extends Omit<RequestInit, 'body'> {
  query?: Record<string, QueryValue>;
  body?: unknown;
}

export interface RelixQClientOptions {
  /** API origin, e.g. https://api.relix-q.dev (no trailing slash required). */
  baseUrl: string;
  /**
   * Static bearer token, or a (possibly async) provider invoked per request so
   * callers can refresh short-lived tokens.
   */
  token?: string | (() => string | null | undefined | Promise<string | null | undefined>);
  /** Extra headers merged into every request. */
  headers?: Record<string, string>;
  /** Max retry attempts for transient failures (429 / 5xx / network). Default 2. */
  maxRetries?: number;
  /** Base backoff in ms; grows exponentially with jitter. Default 300. */
  retryBaseMs?: number;
  /** Injectable fetch (tests / non-global-fetch runtimes). Defaults to global fetch. */
  fetch?: typeof fetch;
}

const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);

function buildQuery(query: RequestOptions['query']): string {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const v of value) params.append(key, String(v));
    } else {
      params.set(key, String(value));
    }
  }
  const qs = params.toString();
  return qs ? `?${qs}` : '';
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseRetryAfter(res: Response): number | null {
  const raw = res.headers.get('retry-after');
  if (!raw) return null;
  const secs = Number(raw);
  return Number.isFinite(secs) ? secs : null;
}

/**
 * Fetch-based, framework-agnostic SDK for the current Relix-Q OSS API.
 * Bearer-token auth, exponential-backoff retries on transient failures, and
 * zod-validated responses. Works in the browser, Node 20+, and edge runtimes
 * (inject `fetch` if no global is present).
 */
export class RelixQClient {
  private readonly baseUrl: string;
  private readonly tokenSource: RelixQClientOptions['token'];
  private readonly extraHeaders: Record<string, string>;
  private readonly maxRetries: number;
  private readonly retryBaseMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: RelixQClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.tokenSource = options.token;
    this.extraHeaders = options.headers ?? {};
    this.maxRetries = options.maxRetries ?? 2;
    this.retryBaseMs = options.retryBaseMs ?? 300;
    const f = options.fetch ?? (globalThis.fetch as typeof fetch | undefined);
    if (!f) {
      throw new Error(
        'No fetch implementation available. Pass `fetch` in RelixQClientOptions for this runtime.',
      );
    }
    this.fetchImpl = f;
  }

  private async resolveToken(): Promise<string | null | undefined> {
    if (typeof this.tokenSource === 'function') return this.tokenSource();
    return this.tokenSource;
  }

  /** Low-level request. Most callers should prefer the resource methods. */
  async request<T>(path: string, schema: z.ZodType<T>, opts: RequestOptions = {}): Promise<T> {
    const { query, body, headers, ...rest } = opts;
    const url = `${this.baseUrl}${path}${buildQuery(query)}`;
    const token = await this.resolveToken();

    const init: RequestInit = {
      ...rest,
      headers: {
        accept: 'application/json',
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...this.extraHeaders,
        ...headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    };

    let lastError: unknown;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      let res: Response;
      try {
        res = await this.fetchImpl(url, init);
      } catch (networkErr) {
        // Network/abort error — retry if attempts remain.
        lastError = networkErr;
        if (attempt < this.maxRetries) {
          await sleep(this.backoff(attempt));
          continue;
        }
        throw networkErr;
      }

      if (res.ok) {
        const json = (await res.json()) as unknown;
        const parsed = schema.safeParse(json);
        if (!parsed.success) {
          throw new ResponseValidationError(path, parsed.error.issues);
        }
        return parsed.data;
      }

      // Non-2xx. Decide whether to retry.
      if (RETRYABLE_STATUS.has(res.status) && attempt < this.maxRetries) {
        const retryAfter = parseRetryAfter(res);
        await sleep(retryAfter !== null ? retryAfter * 1000 : this.backoff(attempt));
        continue;
      }

      throw await this.toError(path, res);
    }

    // Exhausted retries on network errors.
    throw lastError instanceof Error ? lastError : new Error(String(lastError));
  }

  private backoff(attempt: number): number {
    const base = this.retryBaseMs * 2 ** attempt;
    return base + Math.floor(Math.random() * this.retryBaseMs);
  }

  private async toError(path: string, res: Response): Promise<Error> {
    let payload: unknown;
    try {
      payload = await res.json();
    } catch {
      payload = await res.text().catch(() => undefined);
    }
    if (res.status === 401 || res.status === 403) {
      return new AuthenticationRequiredError(path, res.status, payload);
    }
    if (res.status === 429) {
      return new RateLimitedError(path, parseRetryAfter(res), payload);
    }
    return new RelixQApiError(`API ${res.status} ${path}`, res.status, path, payload);
  }

  // --- Resource clients -------------------------------------------------

  readonly findings = {
    list: (
      projectId: string,
      params: { scanId?: string } = {},
    ): Promise<FindingDto[]> =>
      this.request(`/api/v1/projects/${projectId}/findings`, FindingDtoSchema.array(), {
        query: { scanId: params.scanId },
      }),
  };

  readonly scans = {
    start: (projectId: string): Promise<ScanRun> =>
      this.request(`/api/v1/projects/${projectId}/scans`, ScanRunSchema, {
        method: 'POST',
      }),

    list: (projectId: string): Promise<ScanRun[]> =>
      this.request(`/api/v1/projects/${projectId}/scans`, ScanRunSchema.array()),

    get: (scanId: string): Promise<ScanRun> =>
      this.request(`/api/v1/scans/${scanId}`, ScanRunSchema),
  };

  readonly scores = {
    project: (projectId: string): Promise<ProjectScore> =>
      this.request(`/api/v1/scores/projects/${projectId}`, ProjectScoreSchema),

    /** Backward-compatible alias for the latest project score endpoint. */
    readiness: (projectId: string): Promise<ProjectScore> =>
      this.request(`/api/v1/scores/projects/${projectId}`, ProjectScoreSchema),
  };
}
