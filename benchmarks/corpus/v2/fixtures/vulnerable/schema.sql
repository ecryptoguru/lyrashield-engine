-- Synthetic AI-built-app fixture — permissive RLS patterns.

-- CASE:RLS-01 — RLS enabled with a blanket allow-all policy
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "anyone can read profiles" ON public.profiles
  FOR SELECT USING (true);
CREATE POLICY "anyone can write profiles" ON public.profiles
  FOR ALL USING (true) WITH CHECK (true);

-- CASE:RLS-02 — table with no RLS at all
CREATE TABLE public.documents (
  id uuid primary key,
  owner uuid,
  body text
);
