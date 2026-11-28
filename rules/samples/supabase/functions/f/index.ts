const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization" };  // expect: supabase-cors-wildcard
const ok = { "Access-Control-Allow-Origin": "https://app.example.com" };  // ok
export const admin = import.meta.env.SUPABASE_SERVICE_ROLE_KEY;  // ok
