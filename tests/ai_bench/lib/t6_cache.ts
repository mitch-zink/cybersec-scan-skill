import { cache } from "./cache";
import { sessionUser, supabaseAdmin } from "./db";

export async function getReport(req: any, res: any) {
  const user = await sessionUser(req);
  const reportId = req.params.id;
  const hit = cache.get(`report:${reportId}`);
  if (hit) return res.json(hit);
  const { data } = await supabaseAdmin.from("reports").select("*").eq("id", reportId).eq("org_id", user.orgId).single();
  cache.set(`report:${reportId}`, data);
  res.json(data);
}
