"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";

// ---------------------------------------------------------------------------
// Context shape
// ---------------------------------------------------------------------------

export interface TeshtContextValue {
  /** Base URL of the Tesht backend API (e.g. "http://localhost:8000").
   *  When null, server-connected hooks will throw on use. */
  apiUrl: string | null;
  /** Current bearer token for authenticated API requests. */
  authToken: string | null;
  /** Update the stored auth token (e.g. after a demo session is created). */
  setAuthToken: (token: string | null) => void;
}

const TeshtContext = createContext<TeshtContextValue>({
  apiUrl: null,
  authToken: null,
  setAuthToken: () => undefined,
});

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export interface TeshtProviderProps {
  children: ReactNode;
  /** Optional. Base URL of the backend API. Enables server-connected hooks. */
  apiUrl?: string | null;
  /** Optional. Initial auth bearer token. Can be changed via setAuthToken(). */
  authToken?: string | null;
}

export function TeshtProvider({
  children,
  apiUrl = null,
  authToken: initialToken = null,
}: TeshtProviderProps): React.JSX.Element {
  const [authToken, setAuthTokenState] = useState<string | null>(initialToken);

  const setAuthToken = useCallback((token: string | null) => {
    setAuthTokenState(token);
  }, []);

  const value = useMemo<TeshtContextValue>(
    () => ({ apiUrl: apiUrl ?? null, authToken, setAuthToken }),
    [apiUrl, authToken, setAuthToken],
  );

  return (
    <TeshtContext.Provider value={value}>{children}</TeshtContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook: useTesht (internal — access raw context)
// ---------------------------------------------------------------------------

export function useTesht(): TeshtContextValue {
  return useContext(TeshtContext);
}

/** Asserts that apiUrl is configured; throws a clear message otherwise. */
export function useRequireApiUrl(): string {
  const { apiUrl } = useTesht();
  if (!apiUrl) {
    throw new Error(
      "[TeshtProvider] apiUrl is required for server-connected hooks. " +
        "Pass apiUrl prop to <TeshtProvider>.",
    );
  }
  return apiUrl;
}
