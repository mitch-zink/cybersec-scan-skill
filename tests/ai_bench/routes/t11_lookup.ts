import { sessionUser, supabaseAdmin } from "../lib/db";

export async function lookupProject(req: any, res: any) {
  const user = await sessionUser(req);
  const { data } = await supabaseAdmin.from("projects").select("*").eq("id", req.params.id).single();
  if (!data) return res.status(404).json({ error: "not found" });
  if (data.org_id !== user.orgId) return res.status(403).json({ error: "belongs to another organization" });
  res.json(data);
}
