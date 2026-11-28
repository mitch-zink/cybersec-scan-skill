import { sessionUser, supabaseAdmin } from "../lib/db";

export async function listInvoices(req: any, res: any) {
  await sessionUser(req);
  const orgId = req.body.org_id;
  const { data } = await supabaseAdmin.from("invoices").select("*").eq("org_id", orgId);
  res.json(data);
}
