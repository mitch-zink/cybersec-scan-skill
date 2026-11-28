import { isMember, sessionUser, supabaseAdmin } from "../lib/db";

export async function exportOrg(req: any, res: any) {
  const user = await sessionUser(req);
  const org = req.query.org;
  if (!(await isMember(user.id, org))) return res.status(404).end();
  const { data } = await supabaseAdmin.from("invoices").select("*").eq("org_id", org);
  res.setHeader("Content-Type", "text/csv");
  res.send((data || []).map((r: any) => Object.values(r).join(",")).join("\n"));
}
