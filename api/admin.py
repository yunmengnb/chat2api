import os
import time

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

import utils.globals as globals
from app import app, templates
from utils import configs
from utils.admin_store import (
    api_keys,
    create_api_key,
    enabled_models,
    get_api_key_usage,
    find_model,
    mask_secret,
    models,
    runtime_config,
    reset_api_key_usage,
    save_api_keys,
    save_models,
    save_runtime,
    session_value,
    valid_session,
)

PREFIX = f"/{configs.api_prefix}" if configs.api_prefix else ""
ADMIN_ROOT = f"{PREFIX}/admin"
ADMIN_API = f"{ADMIN_ROOT}/api"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
SESSION_COOKIE = "chat2api_admin"


def require_admin(request):
    if not ADMIN_PASSWORD or not valid_session(request.cookies.get(SESSION_COOKIE), ADMIN_PASSWORD):
        raise HTTPException(status_code=401, detail="请先登录管理员后台")


def persist_tokens():
    with open(globals.TOKENS_FILE, "w", encoding="utf-8") as f:
        for token in globals.token_list:
            f.write(token + "\n")


def persist_error_tokens():
    with open(globals.ERROR_TOKENS_FILE, "w", encoding="utf-8") as f:
        for token in globals.error_token_list:
            f.write(token + "\n")


@app.get(ADMIN_ROOT, response_class=HTMLResponse)
async def admin_page(request: Request):
    logged_in = bool(ADMIN_PASSWORD and valid_session(request.cookies.get(SESSION_COOKIE), ADMIN_PASSWORD))
    template = "admin.html" if logged_in else "admin_login.html"
    return templates.TemplateResponse(template, {"request": request, "admin_root": ADMIN_ROOT})


@app.post(f"{ADMIN_ROOT}/login")
async def admin_login(request: Request):
    data = await request.json()
    if not ADMIN_PASSWORD or data.get("password") != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="访问密码错误")
    response = JSONResponse({"ok": True})
    response.set_cookie(SESSION_COOKIE, session_value(ADMIN_PASSWORD), httponly=True, samesite="strict", max_age=604800, path=ADMIN_ROOT)
    return response


@app.post(f"{ADMIN_ROOT}/logout")
async def admin_logout():
    response = RedirectResponse(ADMIN_ROOT, status_code=303)
    response.delete_cookie(SESSION_COOKIE, path=ADMIN_ROOT)
    return response


@app.get(f"{ADMIN_API}/status")
async def admin_status(request: Request):
    require_admin(request)
    unique_tokens = list(dict.fromkeys(globals.token_list))
    errors = set(globals.error_token_list)
    return {
        "version": configs.version,
        "api_base_url": str(request.base_url).rstrip("/") + PREFIX + "/v1",
        "token_total": len(unique_tokens),
        "token_available": len([x for x in unique_tokens if x not in errors]),
        "token_errors": len(errors),
        "api_key_count": len(api_keys),
        "model_count": len(models),
        "runtime": runtime_config,
        "readonly": {
            "api_prefix": configs.api_prefix or "（无）",
            "chatgpt_base_url": configs.chatgpt_base_url,
            "proxy_url": configs.proxy_url or "（未设置）",
            "enable_gateway": configs.enable_gateway,
            "scheduled_refresh": configs.scheduled_refresh,
        },
    }


@app.get(f"{ADMIN_API}/tokens")
async def admin_tokens(request: Request):
    require_admin(request)
    errors = set(globals.error_token_list)
    return {"items": [{"index": i, "masked": mask_secret(token), "status": "error" if token in errors else "available"} for i, token in enumerate(globals.token_list)]}


@app.post(f"{ADMIN_API}/tokens")
async def admin_add_tokens(request: Request):
    require_admin(request)
    data = await request.json()
    incoming = [line.strip() for line in data.get("tokens", "").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    added = 0
    for token in incoming:
        if token not in globals.token_list:
            globals.token_list.append(token)
            added += 1
    persist_tokens()
    return {"ok": True, "added": added}


@app.delete(f"{ADMIN_API}/tokens/{{index}}")
async def admin_delete_token(index: int, request: Request):
    require_admin(request)
    if index < 0 or index >= len(globals.token_list):
        raise HTTPException(status_code=404, detail="Token 不存在")
    token = globals.token_list.pop(index)
    globals.error_token_list[:] = [item for item in globals.error_token_list if item != token]
    persist_tokens()
    persist_error_tokens()
    return {"ok": True}


@app.delete(f"{ADMIN_API}/tokens")
async def admin_clear_tokens(request: Request, errors_only: bool = False):
    require_admin(request)
    if errors_only:
        errors = set(globals.error_token_list)
        globals.token_list[:] = [item for item in globals.token_list if item not in errors]
        globals.error_token_list.clear()
    else:
        globals.token_list.clear()
        globals.error_token_list.clear()
    persist_tokens()
    persist_error_tokens()
    return {"ok": True}


@app.get(f"{ADMIN_API}/keys")
async def admin_keys(request: Request):
    require_admin(request)
    return {"items": [{**item, "masked": mask_secret(item["key"]), "usage": get_api_key_usage(item["id"])} for item in api_keys]}


@app.post(f"{ADMIN_API}/keys")
async def admin_create_key(request: Request):
    require_admin(request)
    data = await request.json()
    return create_api_key(data.get("name"))


@app.patch(f"{ADMIN_API}/keys/{{key_id}}")
async def admin_toggle_key(key_id: str, request: Request):
    require_admin(request)
    item = next((x for x in api_keys if x.get("id") == key_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="API Key 不存在")
    data = await request.json()
    item["enabled"] = bool(data.get("enabled"))
    save_api_keys()
    return {"ok": True}


@app.delete(f"{ADMIN_API}/keys/{{key_id}}/usage")
async def admin_reset_key_usage(key_id: str, request: Request):
    require_admin(request)
    if not any(x.get("id") == key_id for x in api_keys):
        raise HTTPException(status_code=404, detail="API Key 不存在")
    reset_api_key_usage(key_id)
    return {"ok": True}


@app.delete(f"{ADMIN_API}/keys/{{key_id}}")
async def admin_delete_key(key_id: str, request: Request):
    require_admin(request)
    before = len(api_keys)
    api_keys[:] = [x for x in api_keys if x.get("id") != key_id]
    if len(api_keys) == before:
        raise HTTPException(status_code=404, detail="API Key 不存在")
    save_api_keys()
    return {"ok": True}


@app.get(f"{ADMIN_API}/models")
async def admin_models(request: Request):
    require_admin(request)
    return {"items": models}


@app.post(f"{ADMIN_API}/models")
async def admin_create_model(request: Request):
    require_admin(request)
    data = await request.json()
    model_id = str(data.get("id", "")).strip()
    if not model_id or find_model(model_id):
        raise HTTPException(status_code=400, detail="模型 ID 为空或已存在")
    item = {"id": model_id, "name": str(data.get("name") or model_id).strip(), "upstream_model": str(data.get("upstream_model") or model_id).strip(), "enabled": bool(data.get("enabled", True)), "created": int(time.time())}
    models.append(item)
    save_models()
    return item


@app.put(f"{ADMIN_API}/models/{{model_id}}")
async def admin_update_model(model_id: str, request: Request):
    require_admin(request)
    item = find_model(model_id)
    if not item:
        raise HTTPException(status_code=404, detail="模型不存在")
    data = await request.json()
    new_id = str(data.get("id") or model_id).strip()
    if new_id != model_id and find_model(new_id):
        raise HTTPException(status_code=400, detail="新模型 ID 已存在")
    item.update({"id": new_id, "name": str(data.get("name") or new_id).strip(), "upstream_model": str(data.get("upstream_model") or new_id).strip(), "enabled": bool(data.get("enabled", True))})
    save_models()
    return item


@app.delete(f"{ADMIN_API}/models/{{model_id}}")
async def admin_delete_model(model_id: str, request: Request):
    require_admin(request)
    before = len(models)
    models[:] = [x for x in models if x.get("id") != model_id]
    if len(models) == before:
        raise HTTPException(status_code=404, detail="模型不存在")
    save_models()
    return {"ok": True}


@app.put(f"{ADMIN_API}/config")
async def admin_config(request: Request):
    require_admin(request)
    data = await request.json()
    values = {
        "random_token": bool(data.get("random_token")),
        "retry_times": max(0, min(10, int(data.get("retry_times", 3)))),
        "enable_limit": bool(data.get("enable_limit")),
        "history_disabled": bool(data.get("history_disabled")),
    }
    save_runtime(values)
    return {"ok": True, "runtime": runtime_config}
