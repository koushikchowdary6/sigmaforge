import { type FormEvent, useState } from "react";
import { ApiError, fetchCurrentUser, login, type MeResponse } from "../../lib/apiClient";

interface LoginPageProps {
  onLoginSuccess?: (user: MeResponse) => void;
}

/**
 * Real login form -- calls the actual auth API (POST /api/v1/auth/login),
 * then /api/v1/auth/me to confirm the token works end-to-end. Errors are
 * shown as the generic message the backend returns (THREAT_MODEL.md §4.1 --
 * the UI must not invent a more specific message than the API gives it,
 * which would defeat the backend's account-enumeration protection).
 */
export function LoginPage({ onLoginSuccess }: LoginPageProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      await login(email, password);
      const user = await fetchCurrentUser();
      onLoginSuccess?.(user);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} aria-label="Login form">
      <h1>SigmaForge</h1>
      <div>
        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          autoComplete="username"
        />
      </div>
      <div>
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoComplete="current-password"
        />
      </div>
      {error && (
        <p role="alert" data-testid="login-error">
          {error}
        </p>
      )}
      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? "Signing in..." : "Sign in"}
      </button>
    </form>
  );
}
