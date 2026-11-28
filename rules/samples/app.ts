export async function a(db: any, q: string, url: string) {
  db.query("SELECT * FROM t WHERE n = '" + q + "'");  // expect: sql-concat-js
  db.query("SELECT * FROM t WHERE n = $1", [q]);  // ok
  require("child_process").exec("ls " + q);  // expect: os-command-js
  require("child_process").execFile("ls", [q]);  // ok
  fetch(url, { agent: new https.Agent({ rejectUnauthorized: false }) });  // expect: tls-reject-off-js
}
