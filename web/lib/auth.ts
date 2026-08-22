import { UserSession, UserRole } from "../types";
import { api } from "./api";

const SESSION_KEY = "airom_session_v1";

export function saveSession(session: UserSession) {
  if (typeof window !== "undefined") {
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
    api.setToken(session.token);
  }
}

export function loadSession(): UserSession | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  try {
    const session: UserSession = JSON.parse(raw);
    api.setToken(session.token);
    return session;
  } catch {
    localStorage.removeItem(SESSION_KEY);
    return null;
  }
}

export function clearSession() {
  if (typeof window !== "undefined") {
    localStorage.removeItem(SESSION_KEY);
    api.setToken(null);
  }
}

export function hasPermission(userRole: UserRole, requiredRole: UserRole): boolean {
  const hierarchy: Record<UserRole, number> = {
    auditor: 1,
    developer: 2,
    compliance_officer: 3,
    admin: 4,
  };

  return (hierarchy[userRole] || 0) >= (hierarchy[requiredRole] || 0);
}

export function canSignAttestation(role: UserRole): boolean {
  return role === "compliance_officer" || role === "admin";
}

export function canManageTeam(role: UserRole): boolean {
  return role === "admin";
}
