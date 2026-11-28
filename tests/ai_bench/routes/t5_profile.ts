import { sessionUser, supabaseAdmin } from "../lib/db";

export async function getProfile(req: any, res: any) {
  await sessionUser(req);
  const { data } = await supabaseAdmin.from("profiles").select("*").eq("id", req.query.user_id).single();
  res.json(data);
}
