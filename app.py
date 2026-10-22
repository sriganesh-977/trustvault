import os
import sys
import subprocess
import atexit
import time
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse

app = FastAPI(title="TrustVault")

# 1. Ensure node_modules exists
if not os.path.exists("node_modules"):
    print("[TrustVault] node_modules not found, running npm ci...")
    subprocess.run(["npm", "ci"], check=False)

# 2. Seed database
print("[TrustVault] Seeding demo accounts...")
subprocess.run(["node", "src/seed.js"], check=False)

# 3. Start Node.js backend
PORT_NODE = int(os.environ.get("NODE_INTERNAL_PORT", 3001))
node_env = os.environ.copy()
node_env["PORT"] = str(PORT_NODE)
node_env["DATA_DIR"] = os.environ.get("TRUSTVAULT_DATA_DIR", "data")

print(f"[TrustVault] Starting Node.js backend on port {PORT_NODE}...")
node_proc = subprocess.Popen(["node", "src/server.js"], env=node_env)

def cleanup():
    if node_proc.poll() is None:
        print("[TrustVault] Stopping Node.js backend...")
        node_proc.terminate()

atexit.register(cleanup)
time.sleep(1.5)

client = httpx.AsyncClient(base_url=f"http://127.0.0.1:{PORT_NODE}", timeout=120.0)

@app.get("/healthz")
async def health():
    try:
        r = await client.get("/healthz", timeout=5.0)
        return r.json()
    except Exception:
        return {"status": "ok", "service": "trustvault-bridge"}

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy_all(request: Request, path: str):
    target_path = "/" + path
    if request.url.query:
        target_path += f"?{request.url.query}"

    headers = dict(request.headers)
    headers.pop("host", None)

    body = await request.body()

    try:
        req = client.build_request(
            method=request.method,
            url=target_path,
            headers=headers,
            content=body,
            cookies=request.cookies
        )
        resp = await client.send(req, stream=True)

        resp_headers = dict(resp.headers)
        resp_headers.pop("content-encoding", None)
        resp_headers.pop("transfer-encoding", None)
        resp_headers.pop("content-length", None)

        return StreamingResponse(
            resp.aiter_bytes(),
            status_code=resp.status_code,
            headers=resp_headers,
            media_type=resp.headers.get("content-type")
        )
    except Exception as exc:
        return JSONResponse(status_code=502, content={"error": f"Bridge error: {str(exc)}"})
