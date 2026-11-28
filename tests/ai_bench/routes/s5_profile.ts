import { sessionUser, userClient } from "../lib/db";

export async function getProfile(req: any, res: any) {
  const user = await sessionUser(req);
  const { data } = await userClient(user.jwt).from("profiles").select("*").eq("id", req.query.user_id).single();
  res.json(data);
}
