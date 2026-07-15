/**
 * Minimal fetch-based API client for the auth flow (API_SPECIFICATION.md §2).
 *
 * Access tokens are held in memory only (a module-level variable), never in
 * localStorage/sessionStorage -- this bounds token lifetime to the page
 * session and avoids the classic XSS-reads-localStorage token theft vector.
 * The refresh token is likewise kept only in memory for this E0 slice; a
 * later milestone may move it to an httpOnly cookie set by the backend,
 * which would require a corresponding backend change (documented as
 * FUTURE_WORK once the auth subsystem doc lands, per REPO_STRUCTURE.md §2).
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

let accessToken: string | null = null;
let refreshToken: string | null = null;

export function getAccessToken(): string | null {
  return accessToken;
}

export function clearSession(): void {
  accessToken = null;
  refreshToken = null;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface MeResponse {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function parseErrorDetail(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: string };
    return body.detail ?? `Request failed with status ${response.status}`;
  } catch {
    return `Request failed with status ${response.status}`;
  }
}

export async function login(email: string, password: string): Promise<TokenResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorDetail(response));
  }

  const tokens = (await response.json()) as TokenResponse;
  accessToken = tokens.access_token;
  refreshToken = tokens.refresh_token;
  return tokens;
}

export async function logout(): Promise<void> {
  if (!refreshToken) {
    clearSession();
    return;
  }
  await fetch(`${API_BASE_URL}/api/v1/auth/logout`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  clearSession();
}

export async function fetchCurrentUser(): Promise<MeResponse> {
  if (!accessToken) {
    throw new ApiError(401, "Not authenticated");
  }
  const response = await fetch(`${API_BASE_URL}/api/v1/auth/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorDetail(response));
  }
  return (await response.json()) as MeResponse;
}
