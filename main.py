"""
TrustGate — conference demo (M0 skeleton).

FastAPI serves index.html at GET /.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

APP_DIR = Path(__file__).resolve().parent
INDEX_HTML = APP_DIR / "index.html"

app = FastAPI(title="TrustGate", version="0.1.0-m1")


@app.get("/")
async def serve_frontend() -> FileResponse:
    """Serve the single-page demo UI."""
    return FileResponse(INDEX_HTML, media_type="text/html; charset=utf-8")
