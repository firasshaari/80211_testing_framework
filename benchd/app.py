"""The Bench Console web application."""
from __future__ import annotations

import mimetypes
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, RedirectResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from benchd import auth, compare, docsgen, paths, probe as probe_mod, runner, store, testbed

app = FastAPI(title="Bench Console", docs_url=None, redoc_url=None)
paths.ensure()
paths.STATIC.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(paths.STATIC)), name="static")

templates = Jinja2Templates(directory=str(paths.TEMPLATES))
templates.env.filters["pct"] = lambda n, total: (100.0 * n / total) if total else 0.0

OPEN_PATHS = ("/login", "/static", "/healthz")


@app.on_event("startup")
def _startup() -> None:
    fixed = runner.reconcile()
    if fixed:
        print(f"[benchd] marked {fixed} orphaned run(s) as interrupted")


@app.middleware("http")
async def require_login(request: Request, call_next):
    if not any(request.url.path.startswith(p) for p in OPEN_PATHS):
        if not request.session.get("ok"):
            return RedirectResponse("/login", status_code=303)
    return await call_next(request)


# Added *after* require_login on purpose: Starlette makes the most recently
# added middleware the outermost, and the auth check needs the session to have
# been populated before it runs.
app.add_middleware(SessionMiddleware, secret_key=auth.secret_key(),
                   session_cookie="bench_session", max_age=14 * 24 * 3600)


def page(request: Request, template: str, **ctx) -> HTMLResponse:
    ctx.setdefault("busy", runner.busy())
    ctx.setdefault("current", runner.current())
    return templates.TemplateResponse(request, template, ctx)


# ── auth ─────────────────────────────────────────────────────────────────────

@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse(
        request, "login.html",
        {"needs_setup": not auth.configured(), "error": ""})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, password: str = Form(...)):
    if not auth.configured():
        # First boot: whatever is typed becomes the bench password. Better than
        # shipping a default nobody changes.
        auth.set_password(password)
        request.session["ok"] = True
        return RedirectResponse("/", status_code=303)
    if auth.check(password):
        request.session["ok"] = True
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request, "login.html",
        {"needs_setup": False, "error": "That is not the bench password."},
        status_code=401)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ── dashboard and runs ───────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    runs = store.list_runs()
    return page(request, "dashboard.html", runs=runs[:12], total_runs=len(runs),
                summary=docsgen.summary())


@app.get("/runs", response_class=HTMLResponse)
def runs_index(request: Request):
    return page(request, "runs.html", runs=store.list_runs())


@app.get("/run/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: str):
    meta = store.read_meta(run_id)
    if not meta:
        raise HTTPException(404, "no such run")
    has_report = (store.report_dir(run_id) / "index.html").exists()
    return page(request, "run.html", meta=meta, s=compare.summarise(run_id),
                has_report=has_report,
                config=(store.run_dir(run_id) / "testbed.redacted.yaml").read_text()
                if (store.run_dir(run_id) / "testbed.redacted.yaml").exists() else "")


@app.get("/run/{run_id}/console", response_class=HTMLResponse)
def run_console(request: Request, run_id: str):
    meta = store.read_meta(run_id)
    if not meta:
        raise HTTPException(404, "no such run")
    return page(request, "console.html", meta=meta)


@app.get("/run/{run_id}/tail")
def run_tail(run_id: str, offset: int = 0):
    """Incremental console output, so the live page does not refetch the lot."""
    log = store.console_log(run_id)
    meta = store.read_meta(run_id)
    if not log.exists():
        return JSONResponse({"offset": 0, "text": "", "live": bool(meta and meta.is_live)})
    size = log.stat().st_size
    if offset > size:            # the log was truncated: start again
        offset = 0
    with log.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read(200_000)
    return JSONResponse({
        "offset": offset + len(chunk),
        "text": chunk.decode("utf-8", errors="replace"),
        "live": bool(meta and meta.is_live),
        "status": meta.status if meta else "unknown",
    })


@app.post("/run/{run_id}/stop")
def run_stop(request: Request, run_id: str):
    err = runner.stop(run_id)
    return RedirectResponse(f"/run/{run_id}/console" + (f"?error={err}" if err else ""),
                            status_code=303)


@app.post("/run/{run_id}/regenerate")
def run_regenerate(run_id: str):
    ok = runner.regenerate(run_id)
    return RedirectResponse(f"/run/{run_id}" + ("" if ok else "?error=allure+failed"),
                            status_code=303)


@app.post("/run/{run_id}/delete")
def run_delete(run_id: str):
    store.delete_run(run_id)
    return RedirectResponse("/runs", status_code=303)


# ── the Allure report, served as static files ────────────────────────────────

@app.get("/report/{run_id}")
def report_root(run_id: str):
    return RedirectResponse(f"/report/{run_id}/index.html", status_code=303)


@app.get("/report/{run_id}/{path:path}")
def report_file(run_id: str, path: str):
    base = store.report_dir(run_id).resolve()
    target = (base / path).resolve()
    if not str(target).startswith(str(base)):      # no escaping the report dir
        raise HTTPException(403, "nope")
    if not target.is_file():
        raise HTTPException(404, "not in this report")
    kind, _ = mimetypes.guess_type(str(target))
    return FileResponse(target, media_type=kind or "application/octet-stream")


# ── starting a run ───────────────────────────────────────────────────────────

@app.get("/new", response_class=HTMLResponse)
def new_run(request: Request):
    base = testbed.base_dict()
    areas = sorted({r["area"] for r in docsgen.validation_rows()})
    return page(request, "new.html", base=base, areas=areas,
                examples=sorted(r["name"] for r in docsgen.validation_rows()),
                station=(base.get("station") or {}).get("host", ""))


@app.post("/probe")
def probe_ap(ap_host: str = Form(...), ap_user: str = Form("root"),
             ap_password: str = Form(...)):
    cfg = testbed.build(ap_host, ap_user, ap_password)
    validated, err = testbed.validate(cfg)
    if err:
        return JSONResponse({"ok": False, "error": err})
    return JSONResponse(probe_mod.probe(validated))


@app.post("/preflight")
def run_preflight(ap_host: str = Form(...), ap_user: str = Form("root"),
                  ap_password: str = Form(...)):
    cfg = testbed.build(ap_host, ap_user, ap_password)
    validated, err = testbed.validate(cfg)
    if err:
        return JSONResponse({"ok": False, "lines": [err]})
    tmp = paths.RUNS / ".preflight.yaml"
    testbed.write(cfg, tmp)
    try:
        return JSONResponse(runner.preflight(tmp))
    finally:
        tmp.unlink(missing_ok=True)


@app.post("/start")
def start_run(request: Request,
              ap_host: str = Form(...), ap_user: str = Form("root"),
              ap_password: str = Form(...), label: str = Form(""),
              scope_kind: str = Form("full"), scope_value: str = Form(""),
              mode: str = Form("bridge"), cleanup: str = Form("factory_reset"),
              override_preflight: str = Form("")):
    cfg = testbed.build(ap_host, ap_user, ap_password, cleanup=cleanup)
    validated, err = testbed.validate(cfg)
    if err:
        return page(request, "error.html", title="That config will not load",
                    detail=err, back="/new")

    tmp = paths.RUNS / ".preflight.yaml"
    testbed.write(cfg, tmp)
    pre = runner.preflight(tmp)
    tmp.unlink(missing_ok=True)

    if not pre["ok"] and not override_preflight:
        # Refusing here is the whole point. Three long sweeps on this bench were
        # lost to conditions preflight detects in seconds, and every one of them
        # produced failures that read as AP defects.
        return page(request, "blocked.html", pre=pre,
                    form={"ap_host": ap_host, "ap_user": ap_user,
                          "ap_password": ap_password, "label": label,
                          "scope_kind": scope_kind, "scope_value": scope_value,
                          "mode": mode, "cleanup": cleanup})
    pre["overridden"] = bool(not pre["ok"] and override_preflight)

    info = probe_mod.probe(validated)
    ap_info = info.get("ap") or {"host": ap_host}

    run_id, err = runner.start(cfg=cfg, ap_info=ap_info, label=label,
                               scope_kind=scope_kind, scope_value=scope_value,
                               mode=mode, preflight_result=pre)
    if err:
        return page(request, "error.html", title="Could not start", detail=err,
                    back="/new")
    return RedirectResponse(f"/run/{run_id}/console", status_code=303)


# ── comparison ───────────────────────────────────────────────────────────────

@app.get("/compare", response_class=HTMLResponse)
def compare_picker(request: Request, a: str = "", b: str = ""):
    runs = [m for m in store.list_runs() if not m.is_live]
    models = sorted({m.ap.get("model", "") for m in runs if m.ap.get("model")})
    result = compare.compare(a, b) if a and b else None
    return page(request, "compare.html", runs=runs, models=models,
                a=a, b=b, result=result)


# ── documentation ────────────────────────────────────────────────────────────

@app.get("/docs", response_class=HTMLResponse)
def docs_index(request: Request):
    return page(request, "docs_index.html", summary=docsgen.summary())


@app.get("/docs/how-it-works", response_class=HTMLResponse)
def docs_how(request: Request):
    return page(request, "docs_how.html")


@app.get("/docs/validation", response_class=HTMLResponse)
def docs_validation(request: Request):
    return page(request, "docs_validation.html", rows=docsgen.validation_rows(),
                checks=docsgen.check_catalogue(), summary=docsgen.summary())


@app.get("/docs/allure", response_class=HTMLResponse)
def docs_allure(request: Request):
    return page(request, "docs_allure.html")


@app.get("/docs/limits", response_class=HTMLResponse)
def docs_limits(request: Request):
    return page(request, "docs_limits.html")
