import { cache } from "./cache";
import { sessionUser, supabaseAdmin } from "./db";

export async function getReport(req: any, res: any) {
  const user = await sessionUser(req);
  const key = `report:${user.orgId}:${req.params.id}`;
  const hit = cache.get(key);
  if (hit) return res.json(hit);
  const { data } = await supabaseAdmin.from("reports").select("*").eq("id", req.params.id).eq("org_id", user.orgId).single();
  cache.set(key, data);
  res.json(data);
}
