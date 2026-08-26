/**
 * Shared test wrapper: wraps a component in <TeshtProvider>.
 */
import React, { type ReactNode } from "react";
import { TeshtProvider } from "../src/context.js";

export function makeWrapper(
  props: { apiUrl?: string; authToken?: string } = {},
) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <TeshtProvider apiUrl={props.apiUrl} authToken={props.authToken}>
        {children}
      </TeshtProvider>
    );
  };
}
