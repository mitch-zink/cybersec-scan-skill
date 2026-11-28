import { sessionUser, supabaseAdmin } from "./db";

let currentUser: { id: string; orgId: string } | null = null;

export async function withUser(req: any) {
  currentUser = await sessionUser(req);
}

export async function listNotes() {
  await new Promise((r) => setTimeout(r, 5));
  const { data } = await supabaseAdmin.from("notes").select("*").eq("org_id", currentUser!.orgId);
  return data;
}
