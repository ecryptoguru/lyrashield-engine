// Synthetic AI-built-app fixture — clean projection.
import { createClient } from "@supabase/supabase-js"

// CASE:SVCKEY-01 clean — service key never reaches the client
export const supabase = createClient(
  "https://fixture-project.supabase.invalid",
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? ""
)

// CASE:SVCKEY-02 clean — privileged client is server-only
export function getServiceClient() {
  "use server"
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!key) throw new Error("service key unavailable")
  return createClient("https://fixture-project.supabase.invalid", key)
}
