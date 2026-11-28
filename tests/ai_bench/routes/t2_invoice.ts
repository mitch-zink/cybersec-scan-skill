import { sessionUser, supabaseAdmin } from "../lib/db";

export async function getInvoice(req: any, res: any) {
  await sessionUser(req);
  const { data } = await supabaseAdmin.from("invoices").select("*").eq("id", req.params.id).single();
  if (!data) return res.status(404).end();
  res.json(data);
}
