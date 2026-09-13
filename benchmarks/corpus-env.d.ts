/**
 * Ambient typings for benchmark corpus fixtures. Fixtures are scanner input,
 * not buildable product code — they intentionally reference packages and
 * globals that are never installed in this repository.
 */
declare module "@supabase/supabase-js" {
  export function createClient(...args: unknown[]): unknown
}

declare const process: { env: Record<string, string | undefined> }
