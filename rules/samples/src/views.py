import os, subprocess, shlex, requests
from flask import request
def a(cur):
    q = request.args.get("q")
    cur.execute("SELECT * FROM t WHERE n = '%s'" % q)  # expect: taint-sql-py
    cur.execute("SELECT * FROM t WHERE n = %s", (q,))  # ok
    n = int(request.args.get("n"))
    cur.execute(f"SELECT * FROM t LIMIT {n}")  # expect: sql-format-py (pattern rule; the taint rule sees int())
    os.system("ls " + request.form["d"])  # expect: taint-cmd-py
    os.system("ls " + shlex.quote(request.form["d"]))  # ok
    requests.get(request.args.get("u"))  # expect: taint-ssrf-py
    requests.get("https://api.example.com/x")  # ok
