import { sessionUser, supabaseAdmin } from "../lib/db";

export async function getInvoice(req: any, res: any) {
  const user = await sessionUser(req);
  const { data } = await supabaseAdmin
    .from("invoices").select("*").eq("id", req.params.id).eq("org_id", user.orgId).single();
  if (!data) return res.status(404).end();
  res.json(data);
}
