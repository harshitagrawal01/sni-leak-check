"""sni-leak-check: a tiny web app that tells you whether a site's hostname
leaks on the wire, and whether it publishes an Encrypted ClientHello config.

One endpoint does the work (/api/check), the rest is a static page. No database,
no state, no keys. It only reads public DNS, so it is cheap to run and safe to
self-host anywhere.
"""
import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .ech import check

app = FastAPI(title="sni-leak-check", docs_url="/api/docs")

HERE = os.path.dirname(os.path.abspath(__file__))


@app.get("/api/check")
def api_check(domain: str):
    return JSONResponse(check(domain))


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(HERE, "static", "index.html")) as f:
        return f.read()
