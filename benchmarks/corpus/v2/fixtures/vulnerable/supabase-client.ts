// Synthetic AI-built-app fixture — no working credentials, no real endpoints.
import { createClient } from "@supabase/supabase-js"

// CASE:SVCKEY-01 — the service-role key shipped under a public env name
export const supabase = createClient(
  "https://fixture-project.supabase.invalid",
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY ?? "fixture-service-role-placeholder-01"
)

// CASE:SVCKEY-02 — anon-shaped constant actually carrying a privileged key
const SERVICE_KEY = "fixture-service-role-placeholder-02"
export const adminClient = createClient("https://fixture-project.supabase.invalid", SERVICE_KEY)
