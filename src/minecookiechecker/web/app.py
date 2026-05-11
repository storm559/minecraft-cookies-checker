"""FastAPI web UI for interactive cookie checking."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from minecookiechecker.config import Settings
from minecookiechecker.database import AuditDB
from minecookiechecker.parser import (
    parse_cookies_txt,
    parse_single_cookie_header,
    scan_logs_directory,
)
from minecookiechecker.validator import validate_batch

TEMPLATES_DIR = Path(__file__).parent / "templates"


def create_app() -> FastAPI:
    app = FastAPI(title="MineCookieChecker", version="1.0.0")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("index.html", {"request": request})

    @app.post("/check", response_class=JSONResponse)
    async def check_cookies(
        request: Request,
        consent: str = Form(...),
        mode: str = Form("header"),
        cookie_input: str = Form(""),
        file_path: str = Form(""),
        logs_path: str = Form(""),
        dry_run: bool = Form(False),
    ) -> JSONResponse:
        if consent.lower() not in ("yes", "y"):
            return JSONResponse(
                {"error": "Consent not provided. Cannot proceed."},
                status_code=403,
            )

        settings = Settings()
        settings.dry_run = dry_run
        audit_db = AuditDB(settings.db_path)

        operator = os.getenv("USER", "web-operator")
        source_type = mode
        source_path = file_path or logs_path or "<web-input>"

        audit_id = audit_db.log_consent(
            operator=operator,
            consent_method="web-form",
            source_type=source_type,
            source_path=source_path,
        )

        if mode == "header":
            candidates = parse_single_cookie_header(cookie_input)
        elif mode == "file" and file_path:
            candidates = parse_cookies_txt(file_path)
        elif mode == "logs" and logs_path:
            candidates = scan_logs_directory(logs_path)
        else:
            return JSONResponse({"error": "Invalid mode or missing input."}, status_code=400)

        if not candidates:
            return JSONResponse({"message": "No cookie candidates found.", "results": []})

        summary = await validate_batch(
            candidates, settings, audit_db=audit_db, audit_id=audit_id
        )

        return JSONResponse(
            {
                "summary": {
                    "total": summary.total,
                    "valid": summary.valid,
                    "invalid": summary.invalid,
                    "errors": summary.errors,
                    "skipped": summary.skipped,
                },
                "results": [
                    {
                        "cookie_name": r.cookie.name,
                        "cookie_value": r.cookie.redacted_value(),
                        "status": r.status.value,
                        "http_status": r.http_status,
                        "detail": r.detail,
                    }
                    for r in summary.results
                ],
            }
        )

    @app.get("/history", response_class=JSONResponse)
    async def history() -> JSONResponse:
        settings = Settings()
        audit_db = AuditDB(settings.db_path)
        runs = audit_db.get_recent_runs(limit=20)
        return JSONResponse(
            [
                {
                    "id": r.id,
                    "timestamp": str(r.timestamp),
                    "operator": r.operator,
                    "source_type": r.source_type,
                    "total": r.total_cookies,
                    "valid": r.valid_cookies,
                    "invalid": r.invalid_cookies,
                }
                for r in runs
            ]
        )

    return app
