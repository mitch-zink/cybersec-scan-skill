import { analytics } from "./analytics";
import { sessionUser, supabaseAdmin } from "./db";

export async function payInvoice(req: any, res: any) {
  const user = await sessionUser(req);
  const { data: invoice } = await supabaseAdmin
    .from("invoices").update({ paid: true }).eq("id", req.params.id).eq("org_id", user.orgId).select("*").single();
  analytics.track("invoice_paid", invoice);
  res.json({ ok: true });
}
