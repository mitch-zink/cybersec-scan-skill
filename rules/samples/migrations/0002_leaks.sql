CREATE TABLE public.invoices (id uuid, org_id uuid, amount int);
CREATE TABLE public.notes (id uuid, user_id uuid, body text);
ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_open ON public.notes FOR SELECT USING (true);
GRANT SELECT ON public.notes TO anon;
CREATE FUNCTION public.export_all() RETURNS SETOF public.notes LANGUAGE sql SECURITY DEFINER AS $$ SELECT * FROM public.notes; $$;
DO $$ BEGIN RAISE NOTICE 'a;b'; END $$;
