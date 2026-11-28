import { createClient } from "@supabase/supabase-js";

const url = process.env.SUPABASE_URL!;
export const supabaseAdmin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export function userClient(jwt: string) {
  return createClient(url, process.env.SUPABASE_ANON_KEY!, {
    global: { headers: { Authorization: `Bearer ${jwt}` } },
  });
}

export async function sessionUser(req: { headers: Record<string, string> }) {
  const jwt = (req.headers.authorization || "").replace("Bearer ", "");
  const { data } = await supabaseAdmin.auth.getUser(jwt);
  if (!data.user) throw new Error("unauthorized");
  const { data: m } = await supabaseAdmin.from("members").select("org_id").eq("user_id", data.user.id).single();
  return { id: data.user.id, email: data.user.email!, orgId: m!.org_id as string, jwt };
}

export async function isMember(userId: string, orgId: string) {
  const { data } = await supabaseAdmin.from("members").select("user_id").eq("user_id", userId).eq("org_id", orgId);
  return (data || []).length > 0;
}
