import crypto from "node:crypto";
import { supabaseAdmin } from "../lib/db";

export async function billingWebhook(req: any, res: any) {
  const sig = req.headers["x-signature"] || "";
  const want = crypto.createHmac("sha256", process.env.BILLING_SECRET!).update(req.rawBody).digest("hex");
  if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return res.status(400).end();
  const event = JSON.parse(req.rawBody);
  const { data: acct } = await supabaseAdmin.from("billing_accounts").select("org_id").eq("account_id", event.account_id).single();
  if (event.type === "invoice.paid" && acct) {
    await supabaseAdmin.from("subscriptions").update({ status: "active", plan: event.plan }).eq("org_id", acct.org_id);
  }
  res.json({ received: true });
}
