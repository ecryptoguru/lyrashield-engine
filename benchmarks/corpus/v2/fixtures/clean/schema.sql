-- Synthetic AI-built-app fixture — clean projection.

-- CASE:RLS-01 clean — owner-scoped policies
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users read own profile" ON public.profiles
  FOR SELECT USING (auth.uid() = id);
CREATE POLICY "users write own profile" ON public.profiles
  FOR ALL USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

-- CASE:RLS-02 clean — RLS enabled with an owner policy
CREATE TABLE public.documents (
  id uuid primary key,
  owner uuid,
  body text
);
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY "owners only" ON public.documents
  FOR ALL USING (auth.uid() = owner) WITH CHECK (auth.uid() = owner);
