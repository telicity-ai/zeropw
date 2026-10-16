import { createContext, useContext, type CSSProperties } from 'react';
import type { Field } from '../field/field';

export type ToastKind = 'info' | 'warn';
export type Pill =
  | { kind: 'none' }
  | { kind: 'live'; addr: string | null }
  | { kind: 'off' }
  | { kind: 'stopped' };

export interface AppApi {
  field: Field;
  desktop: boolean;
  motionOn: boolean;
  toast(message: string, kind?: ToastKind): void;
  /** Polite live-region message; bursts within 60 ms are joined. */
  announce(message: string): void;
  setPill(p: Pill): void;
}

export const AppContext = createContext<AppApi | null>(null);

export function useApp(): AppApi {
  const api = useContext(AppContext);
  if (!api) throw new Error('AppContext missing');
  return api;
}

/** Stagger index for the reveal animation (`.r` uses --i × 60 ms). */
export const ri = (i: number): CSSProperties => ({ '--i': i }) as CSSProperties;

export const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
