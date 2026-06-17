import { cookies } from 'next/headers';
import { env, SESSION_COOKIE } from './env';

async function authHeader(): Promise<Record<string, string>> {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  return token ? { cookie: `${SESSION_COOKIE}=${token}` } : {};
}

/** GET a JSON resource, forwarding the session cookie. Returns null on non-2xx
 *  or any transport error (so a flaky API never crashes a server-rendered page). */
export async function apiGet<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(`${env.apiBaseUrl}${path}`, {
      headers: { ...(await authHeader()) },
      cache: 'no-store',
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export interface ApiResult<T> {
  ok: boolean;
  status: number;
  data: T | null;
  error?: unknown;
}

/** POST multipart form data (e.g. a file upload), forwarding the session cookie.
 *  Note: do not set content-type — fetch sets the multipart boundary itself. */
export async function apiUpload<T>(path: string, form: FormData): Promise<ApiResult<T>> {
  try {
    const res = await fetch(`${env.apiBaseUrl}${path}`, {
      method: 'POST',
      headers: { ...(await authHeader()) },
      body: form,
      cache: 'no-store',
    });
    let parsed: unknown = null;
    try {
      parsed = await res.json();
    } catch {
      /* empty body */
    }
    return {
      ok: res.ok,
      status: res.status,
      data: res.ok ? (parsed as T) : null,
      error: res.ok ? undefined : parsed,
    };
  } catch {
    // The connection reset mid-upload — typically the body exceeded the server
    // limit (Kestrel aborts with EPIPE before a 413 can be read).
    return { ok: false, status: 0, data: null, error: { error: 'upload_too_large' } };
  }
}

/** Send a JSON body (POST by default), forwarding the session cookie. */
export async function apiSend<T>(
  path: string,
  body?: unknown,
  method = 'POST',
): Promise<ApiResult<T>> {
  try {
    const res = await fetch(`${env.apiBaseUrl}${path}`, {
      method,
      headers: { 'content-type': 'application/json', ...(await authHeader()) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      cache: 'no-store',
    });
    let parsed: unknown = null;
    try {
      parsed = await res.json();
    } catch {
      /* empty body */
    }
    return {
      ok: res.ok,
      status: res.status,
      data: res.ok ? (parsed as T) : null,
      error: res.ok ? undefined : parsed,
    };
  } catch {
    return { ok: false, status: 0, data: null, error: { error: 'failed' } };
  }
}
