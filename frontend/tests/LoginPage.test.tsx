import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LoginPage } from "../src/features/auth/LoginPage";

describe("LoginPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("submits credentials and reports the current user on success", async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: "fake-access",
          refresh_token: "fake-refresh",
          token_type: "bearer",
          expires_in: 900,
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: "u1",
          email: "engineer@corp.com",
          full_name: "Test Engineer",
          role: "detection_engineer",
          is_active: true,
          mfa_enabled: false,
        }),
      });

    const onLoginSuccess = vi.fn();
    render(<LoginPage onLoginSuccess={onLoginSuccess} />);

    await userEvent.type(screen.getByLabelText(/email/i), "engineer@corp.com");
    await userEvent.type(screen.getByLabelText(/password/i), "correct-password");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => expect(onLoginSuccess).toHaveBeenCalledTimes(1));
    expect(onLoginSuccess).toHaveBeenCalledWith(
      expect.objectContaining({ email: "engineer@corp.com", role: "detection_engineer" }),
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("shows the backend's generic error message on failed login without inventing a new one", async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 401,
      json: async () => ({ detail: "Invalid email or password" }),
    });

    render(<LoginPage />);

    await userEvent.type(screen.getByLabelText(/email/i), "engineer@corp.com");
    await userEvent.type(screen.getByLabelText(/password/i), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByTestId("login-error")).toHaveTextContent("Invalid email or password");
  });
});
