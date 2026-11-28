import { sessionUser, supabaseAdmin } from "../lib/db";

export async function acceptInvite(req: any, res: any) {
  const user = await sessionUser(req);
  const { data: invite } = await supabaseAdmin.from("invites").select("*").eq("token", req.body.token).single();
  if (!invite || invite.accepted_at) return res.status(404).end();
  await supabaseAdmin.from("members").insert({ user_id: user.id, org_id: invite.org_id, role: invite.role });
  await supabaseAdmin.from("invites").update({ accepted_at: new Date().toISOString() }).eq("id", invite.id);
  res.json({ ok: true });
}
