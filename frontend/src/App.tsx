import { useState } from "react";
import { LoginPage } from "./features/auth/LoginPage";
import { clearSession, logout, type MeResponse } from "./lib/apiClient";

export function App() {
  const [currentUser, setCurrentUser] = useState<MeResponse | null>(null);

  async function handleLogout() {
    await logout();
    setCurrentUser(null);
  }

  if (!currentUser) {
    return <LoginPage onLoginSuccess={setCurrentUser} />;
  }

  return (
    <div>
      <h1>SigmaForge</h1>
      <p>
        Signed in as {currentUser.full_name} ({currentUser.role})
      </p>
      <button
        onClick={() => {
          clearSession();
          void handleLogout();
        }}
      >
        Sign out
      </button>
    </div>
  );
}
