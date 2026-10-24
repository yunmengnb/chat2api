import hashlib
import hmac
import json
import os
import secrets
import time
from threading import Lock

from utils import configs

DATA_FOLDER = "data"
API_KEYS_FILE = os.path.join(DATA_FOLDER, "api_keys.json")
MODELS_FILE = os.path.join(DATA_FOLDER, "models.json")
RUNTIME_FILE = os.path.join(DATA_FOLDER, "runtime_config.json")
USAGE_FILE = os.path.join(DATA_FOLDER, "api_key_usage.json")
_lock = Lock()

DEFAULT_MODELS = [
    {"id": "gpt-4o", "upstream_model": "gpt-4o", "name": "GPT-4o", "enabled": True},
    {"id": "gpt-4o-mini", "upstream_model": "gpt-4o-mini", "name": "GPT-4o Mini", "enabled": True},
    {"id": "o3-mini", "upstream_model": "o3-mini", "name": "o3-mini", "enabled": True},
]
RUNTIME_DEFAULTS = {
    "random_token": configs.random_token,
    "retry_times": configs.retry_times,
    "enable_limit": configs.enable_limit,
    "history_disabled": configs.history_disabled,
}


def _load(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = json.load(f)
            return value
    except (OSError, ValueError):
        return default


def _save(path, value):
    os.makedirs(DATA_FOLDER, exist_ok=True)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
    os.replace(temporary, path)


api_keys = _load(API_KEYS_FILE, [])
models = _load(MODELS_FILE, DEFAULT_MODELS)
api_key_usage = _load(USAGE_FILE, {})
runtime_config = {**RUNTIME_DEFAULTS, **_load(RUNTIME_FILE, {})}


def apply_runtime_config():
    configs.random_token = bool(runtime_config["random_token"])
    configs.retry_times = max(0, min(10, int(runtime_config["retry_times"])))
    configs.enable_limit = bool(runtime_config["enable_limit"])
    configs.history_disabled = bool(runtime_config["history_disabled"])

    # ChatService historically imports these values directly.
    try:
        import chatgpt.ChatService as chat_service_module
        chat_service_module.enable_limit = configs.enable_limit
        chat_service_module.history_disabled = configs.history_disabled
    except ImportError:
        pass


apply_runtime_config()


def create_api_key(name):
    item = {
        "id": secrets.token_hex(8),
        "name": (name or "未命名 Key").strip()[:80],
        "key": "sk-managed-" + secrets.token_urlsafe(30),
        "enabled": True,
        "created_at": int(time.time()),
    }
    with _lock:
        api_keys.append(item)
        _save(API_KEYS_FILE, api_keys)
    return item


def resolve_api_key(value):
    for item in api_keys:
        if hmac.compare_digest(item.get("key", ""), value):
            return item if item.get("enabled", True) else None
    return None


def is_managed_key_format(value):
    return value.startswith("sk-managed-")


def mask_secret(value):
    if len(value) <= 12:
        return "****"
    return value[:6] + "…" + value[-5:]


def enabled_models():
    return [item for item in models if item.get("enabled", True)]


def find_model(model_id):
    return next((item for item in models if item.get("id") == model_id), None)


def session_value(password):
    stamp = str(int(time.time()) // 86400)
    signature = hmac.new(password.encode(), stamp.encode(), hashlib.sha256).hexdigest()
    return stamp + "." + signature


def valid_session(value, password):
    if not value or "." not in value:
        return False
    stamp, signature = value.split(".", 1)
    try:
        valid_day = abs(int(stamp) - int(time.time()) // 86400) <= 7
    except ValueError:
        return False
    expected = hmac.new(password.encode(), stamp.encode(), hashlib.sha256).hexdigest()
    return valid_day and hmac.compare_digest(signature, expected)


def save_api_keys():
    with _lock:
        _save(API_KEYS_FILE, api_keys)


def get_api_key_usage(key_id):
    return {
        "request_count": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "updated_at": 0,
        **api_key_usage.get(key_id, {}),
    }


def record_api_key_usage(key_id, usage):
    if not key_id:
        return
    with _lock:
        item = api_key_usage.setdefault(key_id, {})
        item["request_count"] = int(item.get("request_count", 0)) + 1
        for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
            item[field] = int(item.get(field, 0)) + int(usage.get(field, 0))
        item["updated_at"] = int(time.time())
        _save(USAGE_FILE, api_key_usage)


def reset_api_key_usage(key_id):
    with _lock:
        api_key_usage.pop(key_id, None)
        _save(USAGE_FILE, api_key_usage)


def save_models():
    with _lock:
        _save(MODELS_FILE, models)


def save_runtime(values):
    runtime_config.update(values)
    with _lock:
        _save(RUNTIME_FILE, runtime_config)
    apply_runtime_config()
