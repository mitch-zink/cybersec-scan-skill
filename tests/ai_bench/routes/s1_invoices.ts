import { sessionUser, supabaseAdmin } from "../lib/db";

export async function listInvoices(req: any, res: any) {
  const user = await sessionUser(req);
  const { data } = await supabaseAdmin.from("invoices").select("*").eq("org_id", user.orgId);
  res.json(data);
}
