import { supabaseAdmin } from "../lib/db";

export async function billingWebhook(req: any, res: any) {
  const event = req.body;
  if (event.type === "invoice.paid") {
    await supabaseAdmin.from("subscriptions").update({ status: "active", plan: event.plan })
      .eq("org_id", event.org_id);
  }
  res.json({ received: true });
}
