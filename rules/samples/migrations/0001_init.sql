-- fixture: tenant table with RLS on and a proper policy
CREATE TABLE IF NOT EXISTS public.orders (id uuid primary key, tenant_id uuid not null, total int);
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_tenant ON public.orders FOR ALL USING (tenant_id = auth.uid());
