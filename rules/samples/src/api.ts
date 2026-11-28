export async function h(req: any, db: any) {
  const id = req.body.id;
  await db.query("SELECT * FROM t WHERE id = " + id);  // expect: taint-sql-js
  await db.query("SELECT * FROM t WHERE id = $1", [id]);  // ok
  await fetch(req.query.url);  // expect: taint-ssrf-js
  await fetch("https://api.example.com/x");  // ok
}
export const admin = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;  // expect: supabase-service-key-client
export const anon = import.meta.env.VITE_SUPABASE_ANON_KEY;  // ok
export async function k(req: any) {
  const r = await (await fetch("https://api.example.com/x")).json();
  await fetch(r.next);  // ok (a response, not request data)
  await fetch(`${process.env.SB}/rest/v1/t?id=eq.${req.query.id}`);  // ok (fixed host)
  await fetch(`https://oauth2.example.com/revoke?token=${req.body.t}`);  // ok (fixed host)
}
