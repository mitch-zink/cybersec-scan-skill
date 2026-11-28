import os, subprocess, hashlib, pickle, yaml, requests, urllib.request
def a(cur, q, base, name, url):
    cur.execute(f"SELECT * FROM t WHERE n = '{q}'")  # expect: sql-format-py
    cur.execute("SELECT * FROM t WHERE n = ?", (q,))  # ok
    os.system(f"ls {q}")  # expect: os-command-py
    subprocess.run(["ls", q])  # ok
    subprocess.run(q, shell=True)  # expect: os-command-py
    open(os.path.join(base, name), "r")  # expect: path-join-open-py
    requests.get(url)  # ok (a function argument, not request data)
    requests.get("https://api.example.com/v1")  # ok
    hashlib.md5(q.encode())  # expect: weak-hash-py
    hashlib.sha256(q.encode())  # ok
    pickle.loads(q)  # expect: unsafe-deserialize-py
    yaml.load(q)  # expect: unsafe-deserialize-py
    yaml.safe_load(q)  # ok
    requests.get("https://x.example", verify=False)  # expect: tls-verify-off-py
