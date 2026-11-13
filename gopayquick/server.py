# -*- coding: utf-8 -*-
"""GoPay Quick CDK —— 独立卡密支付服务（不修改 19080 主服务）。

启动: python gopayquick/server.py   (默认端口 19100, GOPAY_QUICK_PORT 可覆盖)
"""
import json
import os
import re
import secrets
import string
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote

ROOT = Path(__file__).resolve().parents[1]
for _p in (str(ROOT), str(ROOT / "app" / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gopay import server as base  # noqa: E402
from opai.core.payment_inbox import ProxyPreflightError, _claim_gopay_reward  # noqa: E402

# ---------- 复用 19080 主服务的既有链路 ----------
payment = base.payment
register = base.register
pin_manager = base.pin_manager
_sanitize_public_error = base._sanitize_public_error
_parse_midtrans_links = base._parse_midtrans_links
_parse_proxy_list = base._parse_proxy_list
_pick_proxy = base._pick_proxy
_poll_imported_sms_code = base._poll_imported_sms_code
_account_worker_lock = base._account_worker_lock
_pick_relaxed_payment_account = base._pick_relaxed_payment_account
_claim_pool_phone = base._claim_pool_phone
_mark_pool_phone = base._mark_pool_phone
_find_gopay_account = base._find_gopay_account
_release_gopay_midtrans_binding = base._release_gopay_midtrans_binding

PORT = int(os.environ.get("GOPAY_QUICK_PORT") or "19100")
TARGET_PIN = os.environ.get("GOPAY_QUICK_PIN") or "847152"
STOCK_WAIT_SEC = int(os.environ.get("GOPAY_QUICK_STOCK_WAIT") or "300")
MAX_WORKERS = 4
QUICK_MAX_ACCOUNT_ATTEMPTS = int(os.environ.get("GOPAY_QUICK_MAX_ACCOUNT_ATTEMPTS", "5"))
MAX_JSON_BODY_BYTES = int(os.environ.get("GOPAY_QUICK_MAX_JSON_BODY_BYTES", str(1024 * 1024)))
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class RequestBodyTooLarge(ValueError):
    pass

CDK_PATH = ROOT / "config" / "cdk_keys.json"
CDK_RE = re.compile(r"^GQ-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")
_cdk_lock = threading.RLock()
quick_jobs = {}
quick_jobs_lock = threading.RLock()
quick_batches = {}
_quick_slots = threading.BoundedSemaphore(MAX_WORKERS)


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _page():
    return (ROOT / "gopayquick" / "index.html").read_text(encoding="utf-8")


# ================= CDK 卡密 =================
def _save_cdk_store(data):
    CDK_PATH.parent.mkdir(exist_ok=True)
    tmp = CDK_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(CDK_PATH)


def _load_cdk_store():
    try:
        data = json.loads(CDK_PATH.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    keys = data.get("keys")
    if not isinstance(keys, list):
        keys = []
    token = str(data.get("admin_token") or "").strip()
    if not token:
        token = secrets.token_hex(8)
        data["admin_token"] = token
        data["keys"] = keys
        _save_cdk_store(data)
    return {"admin_token": token, "keys": keys}


def _normalize_cdk(code):
    value = re.sub(r"[\s\-]+", "-", str(code or "").strip().upper())
    return value


def _mask_cdk(code):
    norm = _normalize_cdk(code)
    if CDK_RE.match(norm):
        return "GQ-XXXX-XXXX-XXXX-" + norm.rsplit("-", 1)[-1]
    return "GQ-••••"


def _cdk_summary_locked(data):
    keys = data.get("keys") or []
    unused = sum(1 for k in keys if str(k.get("status") or "").strip() == "unused")
    used = sum(1 for k in keys if str(k.get("status") or "").strip() == "used")
    return {"total": len(keys), "unused": unused, "used": used}


def _cdk_summary():
    with _cdk_lock:
        return _cdk_summary_locked(_load_cdk_store())


def _cdk_remaining(norm):
    with _cdk_lock:
        data = _load_cdk_store()
        for k in data["keys"]:
            if str(k.get("code") or "").upper() == norm:
                quota = max(1, int(k.get("quota") or 1))
                used_count = max(0, int(k.get("used_count") or 0))
                return max(0, quota - used_count)
    return 0


def _verify_cdk(code, *, consume=False, used_by=""):
    norm = _normalize_cdk(code)
    if not CDK_RE.match(norm):
        raise ValueError("CDK 格式无效，应为 GQ-XXXX-XXXX-XXXX-XXXX")
    with _cdk_lock:
        data = _load_cdk_store()
        for k in data["keys"]:
            if str(k.get("code") or "").upper() == norm:
                status = str(k.get("status") or "").strip()
                if status == "used":
                    raise ValueError("CDK 已使用，请更换新的 CDK")
                if status != "unused":
                    raise ValueError("CDK 状态异常，请联系管理员")
                quota = max(1, int(k.get("quota") or 1))
                used_count = max(0, int(k.get("used_count") or 0))
                if consume:
                    used_count += 1
                    k["used_count"] = used_count
                    if used_count >= quota:
                        k["status"] = "used"
                        k["used_at"] = _now()
                    k["used_by"] = used_by
                    _save_cdk_store(data)
                summary = _cdk_summary_locked(data)
                return {
                    "code": norm,
                    "remaining": max(0, quota - used_count),
                    "quota": quota,
                    "used_count": used_count,
                    "total_unused": summary["unused"],
                }
        raise ValueError("CDK 不存在，请检查后重试")


def _generate_cdk_codes(count):
    charset = string.ascii_uppercase + string.digits
    codes = set()
    guard = 0
    while len(codes) < count and guard < count * 20:
        guard += 1
        groups = ["".join(secrets.choice(charset) for _ in range(4)) for _ in range(4)]
        codes.add("GQ-" + "-".join(groups))
    return sorted(codes)


# ================= Quick 任务 =================
def _public_job(job):
    clean = dict(job)
    clean.pop("proxies", None)
    clean.pop("token", None)
    clean.pop("target_pin", None)
    clean["cdk"] = _mask_cdk(clean.get("cdk") or "")
    return clean


def _list_public_jobs(limit=40):
    with quick_jobs_lock:
        rows = [_public_job(j) for j in quick_jobs.values()]
    rows.sort(key=lambda j: j.get("created_at") or "", reverse=True)
    for row in rows:
        logs = row.get("logs") or []
        if len(logs) > 50:
            row["logs"] = logs[-50:]
    return rows[:limit]


def _get_job(job_id):
    with quick_jobs_lock:
        job = quick_jobs.get(job_id)
        return dict(job) if job else None


def _log(job_id, text):
    with quick_jobs_lock:
        job = quick_jobs.get(job_id)
        if not job:
            return
        job.setdefault("logs", []).append({"ts": _now(), "text": text})
        if len(job["logs"]) > 500:
            job["logs"] = job["logs"][-500:]
        job["updated_at"] = _now()


def _set_job(job_id, **fields):
    with quick_jobs_lock:
        job = quick_jobs.get(job_id)
        if not job:
            return
        job.update(fields)
        job["updated_at"] = _now()


def _fail_job(job_id, error):
    with quick_jobs_lock:
        job = quick_jobs.get(job_id)
        if not job:
            return
        job["status"] = "failed"
        job["step"] = "done"
        job["error"] = error
        job["finished_at"] = _now()
        job["updated_at"] = _now()
        job.setdefault("logs", []).append({"ts": _now(), "text": "失败：" + error})
    _update_batch_counts(job.get("batch_id") or "")


def _succeed_job(job_id):
    with quick_jobs_lock:
        job = quick_jobs.get(job_id)
        if not job:
            return
        cdk = str(job.get("cdk") or "")
        job["status"] = "succeeded"
        job["step"] = "done"
        job["finished_at"] = _now()
        job["updated_at"] = _now()
        job.setdefault("logs", []).append({"ts": _now(), "text": "支付成功，CDK 已核销 1 次"})
    try:
        if cdk:
            _verify_cdk(cdk, consume=True, used_by=job_id)
    except Exception:
        pass
    _update_batch_counts(job.get("batch_id") or "")


def _cancel_job(job_id):
    job = _get_job(job_id)
    if not job:
        return False
    if job.get("status") in {"succeeded", "failed", "cancelled"}:
        return True
    _set_job(job_id, status="cancelled", step="done", finished_at=_now(), error="任务已取消")
    _log(job_id, "任务已取消")
    pid = job.get("payment_job_id") or ""
    if pid:
        try:
            payment.cancel(pid)
        except Exception:
            pass
    _update_batch_counts(job.get("batch_id") or "")
    return True


def _update_batch_counts(batch_id):
    if not batch_id:
        return
    with quick_jobs_lock:
        jobs = [j for j in quick_jobs.values() if j.get("batch_id") == batch_id]
        batch = quick_batches.get(batch_id)
        if batch is None:
            return
        batch["total"] = len(jobs)
        batch["finished"] = sum(1 for j in jobs if j.get("status") in {"succeeded", "failed", "cancelled"})
        batch["succeeded"] = sum(1 for j in jobs if j.get("status") == "succeeded")
        batch["failed"] = sum(1 for j in jobs if j.get("status") == "failed")
        if batch["finished"] == batch["total"] and batch["total"]:
            batch["status"] = "done"


def _wait_underlying(uid, quick_id, getter, submitter, label, timeout_sec):
    """等待底层任务到达终态；waiting_otp 时自动轮询短信，找不到则挂起等待人工输入。"""
    if not uid:
        return {"ok": False, "error": label + "任务未创建"}
    deadline = time.time() + timeout_sec
    seen = set()
    while time.time() < deadline:
        quick = _get_job(quick_id)
        if quick is None or str(quick.get("status") or "") == "cancelled":
            return {"ok": False, "error": "任务已取消", "cancelled": True}
        cur = getter(uid) or {}
        status = str(cur.get("status") or "")
        if status == "waiting_otp":
            if str(quick.get("status") or "") != "awaiting_otp":
                _set_job(quick_id, status="awaiting_otp")
            phone = str(quick.get("phone") or "")
            managed_registration = getattr(submitter, "__self__", None) is register
            code = _poll_imported_sms_code(phone, seen) if phone and not managed_registration else ""
            if code and code not in seen:
                seen.add(code)
                try:
                    submitter(uid, code)
                    _log(quick_id, "[" + label + "] 已自动提交验证码（已脱敏）")
                    continue
                except Exception:
                    pass
            time.sleep(1)
            continue
        if status not in {"running", "linking", "pending"}:
            if status == "success":
                return {"ok": True, "message": str(cur.get("message") or label + "成功")}
            return {"ok": False, "error": str(cur.get("message") or cur.get("error") or label + "失败: " + status)}
        if str(quick.get("status") or "") == "awaiting_otp":
            _set_job(quick_id, status="running")
        time.sleep(1)
    return {"ok": False, "error": label + "等待超时（" + str(timeout_sec) + "s）"}


def _ensure_pin_with_job(account, target_pin, job_id):
    phone = str(account.get("phone") or "").strip()
    saved = str(account.get("pin") or "").strip()
    setup_status = str(account.get("pin_setup_status") or "").strip()

    def pin_wait(uid):
        with quick_jobs_lock:
            if quick_jobs.get(job_id):
                quick_jobs[job_id]["pin_job_id"] = uid
                quick_jobs[job_id]["otp_target"] = "pin"
        return _wait_underlying(uid, job_id, lambda jid: pin_manager.get(jid) or {},
                                pin_manager.submit_otp, "PIN", 240)

    if re.fullmatch(r"\d{6}", saved) and setup_status == "configured":
        return {"ok": True, "pin": saved, "note": "使用本地已保存 PIN"}
    if setup_status != "configured":
        last_err = ""
        for candidate in base._pin_candidates(target_pin):
            try:
                job = pin_manager.start(phone=phone, old_pin="", new_pin=candidate, mode="setup")
                result = pin_wait(str((job or {}).get("id") or ""))
                if result["ok"]:
                    note = "已为新账号设置 PIN"
                    if candidate != target_pin:
                        note += f"（目标 PIN {target_pin} 被 GoPay 拒绝，已改用 {candidate}）"
                    return {"ok": True, "pin": candidate, "note": note}
                last_err = result["error"] or last_err
                if not base._is_pin_policy_rejection(result):
                    break
            except Exception as exc:
                last_err = _sanitize_public_error(exc)
                break
        return {"ok": False, "error": last_err or "PIN 设置失败"}
    last_err = ""
    for candidate in base._pin_candidates(target_pin):
        try:
            job = pin_manager.start(phone=phone, old_pin="", new_pin=candidate, mode="forgot")
            result = pin_wait(str((job or {}).get("id") or ""))
            if result["ok"]:
                note = "忘记 PIN 已重置"
                if candidate != target_pin:
                    note += f"（目标 PIN {target_pin} 被 GoPay 拒绝，已改用 {candidate}）"
                return {"ok": True, "pin": candidate, "note": note}
            last_err = result["error"] or last_err
            if not base._is_pin_policy_rejection(result):
                break
        except Exception as exc:
            last_err = _sanitize_public_error(exc)
            break
    return {"ok": False, "error": last_err or "忘记 PIN 重置失败"}


def _pool_login(job_id, target_pin, proxy):
    phone, row = _claim_pool_phone()
    if not phone:
        return {"ok": False, "error": "号码池没有“待登录”号码"}
    try:
        job = register.start(
            source="pool",
            phone=phone,
            sms_url=str((row or {}).get("sms_url") or ""),
            pin=target_pin,
            proxy=proxy,
            login_existing=True, change_pin_after_login=False, new_pin="",
        )
    except Exception as exc:
        _mark_pool_phone(phone, "login_failed")
        return {"ok": False, "error": phone + " 登录启动失败: " + _sanitize_public_error(exc)}
    uid = str((job or {}).get("id") or "")
    with quick_jobs_lock:
        if quick_jobs.get(job_id):
            quick_jobs[job_id]["register_job_id"] = uid
            quick_jobs[job_id]["otp_target"] = "register"
            quick_jobs[job_id]["phone"] = phone
    result = _wait_underlying(uid, job_id, lambda jid: register.get(jid) or {},
                              register.submit_otp, "登录", 360)
    if not result["ok"]:
        _mark_pool_phone(phone, "login_failed")
        result["error"] = phone + " " + result["error"]
        return result
    account, _idx = _find_gopay_account(phone)
    if account is None:
        _mark_pool_phone(phone, "login_failed")
        return {"ok": False, "error": phone + " 登录成功但本地账号记录未找到"}
    pin_prep = _ensure_pin_with_job(account, target_pin, job_id)
    if not pin_prep["ok"]:
        _mark_pool_phone(phone, "login_failed")
        return {"ok": False, "error": phone + " PIN 处理失败: " + pin_prep["error"]}
    try:
        if int(account.get("balance", 0) or 0) < 1:
            reward = _claim_gopay_reward(phone)
            if int(reward.get("balance", 0) or 0) >= 1:
                refreshed, _idx = _find_gopay_account(phone)
                if refreshed is not None:
                    account = refreshed
    except Exception as exc:
        print("pool account reward warmup failed:", exc, file=sys.stderr, flush=True)
    _mark_pool_phone(phone, "available", "registered")
    return {"ok": True, "account": account, "pin": pin_prep["pin"], "message": phone + " 登录成功"}


def _acquire_smsbower_account(job_id, target_pin, proxy):
    try:
        job = register.start(
            source="smsbower",
            phone="",
            pin=target_pin,
            proxy=proxy,
            login_existing=True,
            change_pin_after_login=False,
            new_pin="",
        )
    except Exception as exc:
        return {"ok": False, "error": "SMSBower 取号/登录启动失败: " + _sanitize_public_error(exc)}
    uid = str((job or {}).get("id") or "")
    phone = str((job or {}).get("phone") or "")
    with quick_jobs_lock:
        if quick_jobs.get(job_id):
            quick_jobs[job_id]["register_job_id"] = uid
            quick_jobs[job_id]["otp_target"] = "register"
            if phone:
                quick_jobs[job_id]["phone"] = phone
    _log(job_id, "SMSBower 取号中：" + (phone or "等待下发号码"))
    result = _wait_underlying(uid, job_id, lambda jid: register.get(jid) or {},
                              register.submit_otp, "登录", 420)
    if not result["ok"]:
        return result
    if not phone:
        cur = register.get(uid) or {}
        phone = str(cur.get("phone") or "")
    account, _idx = _find_gopay_account(phone)
    if account is None:
        return {"ok": False, "error": "SMSBower 已有账号登录成功但本地账号记录未找到: " + phone}
    try:
        if int(account.get("balance", 0) or 0) < 1:
            reward = _claim_gopay_reward(phone)
            if int(reward.get("balance", 0) or 0) >= 1:
                refreshed, _idx = _find_gopay_account(phone)
                if refreshed is not None:
                    account = refreshed
    except Exception as exc:
        print("smsbower account reward warmup failed:", exc, file=sys.stderr, flush=True)
    return {"ok": True, "account": account, "pin": target_pin,
            "message": "SMSBower 已有账号 " + phone + " 登录完成"}


def _acquire_account(job_id, proxies, target_pin, skip_phones=None):
    account = _pick_relaxed_payment_account(skip_phones)
    if account is not None:
        return account, ""
    proxy = _pick_proxy(proxies) or ""
    fresh = _pool_login(job_id, target_pin, proxy)
    if fresh["ok"]:
        return fresh["account"], fresh["message"]
    if "号码池没有" in fresh["error"]:
        _set_job(job_id, status="waiting_for_stock", step="phone")
        _log(job_id, "暂无可用账号，SMSBower 预登录池补号中（一次取 " + str(base.SMSBOWER_POOL_BATCH) + " 个号筛选登录）…")
        _trigger_quick_pool(target_pin)
        account, note = _wait_pool_account(job_id, target_pin, base.SMSBOWER_POOL_WAIT_SEC, skip_phones=skip_phones)
        if account is not None:
            return account, note
        if note == "任务已取消":
            return None, note
        fresh = _acquire_smsbower_account(job_id, target_pin, proxy)
        if fresh["ok"]:
            return fresh["account"], fresh["message"]
        return None, fresh.get("error") or "没有可用 GoPay 账号"
    for _ in range(2):
        account = _pick_relaxed_payment_account(skip_phones)
        if account is not None:
            return account, ""
        fresh = _pool_login(job_id, target_pin, proxy)
        if fresh["ok"]:
            return fresh["account"], fresh["message"]
    fresh = _acquire_smsbower_account(job_id, target_pin, proxy)
    if fresh["ok"]:
        return fresh["account"], fresh["message"]
    return None, fresh.get("error") or "没有可用 GoPay 账号"


def _trigger_quick_pool(target_pin):
    with base._pool_lock:
        base._pool_state["target_pin"] = target_pin
    base._pool_state["wake"].set()


def _wait_pool_account(job_id, target_pin, timeout_sec, skip_phones=None):
    deadline = time.time() + max(int(timeout_sec or 180), 600)
    idle_since = None
    while time.time() < deadline:
        if _get_job(job_id)["status"] == "cancelled":
            return None, "任务已取消"
        account = _pick_relaxed_payment_account(skip_phones)
        if account is not None:
            return account, ""
        with base._pool_lock:
            pool_working = base._pool_inflight > 0
            cooldown_until = base._pool_state.get("rate_limit_until") or 0.0
        if pool_working or time.time() < cooldown_until:
            idle_since = None
            time.sleep(5)
            continue
        base._pool_state["wake"].set()
        if idle_since is None:
            idle_since = time.time()
        elif time.time() - idle_since > 60:
            return None, "等待预登录池超时（SMSBower 长时间无可用号码）"
        time.sleep(2)
    return None, "等待预登录池超时"


def _quick_smsbower_pool_needed():
    with quick_jobs_lock:
        has_active = any(
            str(j.get("status") or "") in {"running", "waiting_for_stock", "awaiting_otp", "linking"}
            for j in quick_jobs.values()
        )
    if not has_active:
        return 0
    available = base._count_payable_accounts()
    return max(0, base.SMSBOWER_POOL_BATCH - available)


def _log_active_quick_job(text):
    with quick_jobs_lock:
        for j in quick_jobs.values():
            if str(j.get("status") or "") in {"running", "waiting_for_stock", "awaiting_otp", "linking"}:
                j.setdefault("logs", []).append({"ts": _now(), "text": str(text)})
                if len(j["logs"]) > 500:
                    j["logs"] = j["logs"][-500:]
                j["updated_at"] = _now()


def _quick_smsbower_pool_proxies():
    with quick_jobs_lock:
        active = [
            j for j in quick_jobs.values()
            if str(j.get("status") or "") in {"running", "waiting_for_stock", "awaiting_otp", "linking"}
        ]
    merged = []
    for j in active:
        for p in (j.get("proxies") or []):
            p = str(p or "").strip()
            if p and p not in merged:
                merged.append(p)
    return merged


def _start_quick_smsbower_screen_workers():
    for _idx in range(max(1, base.SMSBOWER_POOL_CONCURRENCY)):
        threading.Thread(
            target=base._smsbower_pool_screen_worker,
            args=(_quick_smsbower_pool_needed, "quick pool"),
            kwargs={
                "log_fn": _log_active_quick_job,
                "proxy_fn": lambda: _pick_proxy(_quick_smsbower_pool_proxies()),
                "index": _idx,
            },
            daemon=True,
            name="quick-screen-" + str(_idx),
        ).start()


def _wait_for_stock(job_id, proxies, target_pin):
    _set_job(job_id, status="waiting_for_stock", step="phone")
    _log(job_id, "暂无可用账号，等待 SMSBower 预登录池补号…")
    _trigger_quick_pool(target_pin)
    account, note = _wait_pool_account(job_id, target_pin, STOCK_WAIT_SEC)
    if account is not None:
        return account, note
    if note == "任务已取消":
        return None, note
    fresh = _acquire_smsbower_account(job_id, target_pin, _pick_proxy(proxies) or "")
    if fresh["ok"]:
        return fresh["account"], fresh["message"]
    return None, note or "等待手机库存超时，无可用 GoPay 账号"


def _run_quick_job(job_id):
    job = _get_job(job_id)
    url = job.get("url") or ""
    proxies = job.get("proxies") or []
    target_pin = job.get("target_pin") or TARGET_PIN
    cdk = job.get("cdk") or ""
    try:
        if _cdk_remaining(_normalize_cdk(cdk)) <= 0:
            _fail_job(job_id, "CDK 额度已用完，无法继续执行")
            return
        _set_job(job_id, status="running", step="phone")
        _log(job_id, "任务开始，正在匹配手机库存")
        skipped_phones = set()
        for attempt in range(1, QUICK_MAX_ACCOUNT_ATTEMPTS + 1):
            if _get_job(job_id)["status"] == "cancelled":
                return
            account, note = _acquire_account(job_id, proxies, target_pin, skip_phones=skipped_phones)
            if account is None:
                if note == "任务已取消":
                    _set_job(job_id, status="cancelled", step="done", finished_at=_now(), error="任务已取消")
                    _update_batch_counts(job.get("batch_id") or "")
                else:
                    _fail_job(job_id, note)
                return
            phone = str(account.get("phone") or "").strip()
            if note:
                _log(job_id, note)
            lock = _account_worker_lock(phone)
            if not lock.acquire(blocking=False):
                skipped_phones.add(phone)
                _log(job_id, "账号 " + phone + " 正被其他任务占用，尝试更换账号（" + str(attempt) + "/" + str(QUICK_MAX_ACCOUNT_ATTEMPTS) + "）")
                continue
            try:
                account, _idx = _find_gopay_account(phone)
                if account is None:
                    skipped_phones.add(phone)
                    continue
                _set_job(job_id, phone=phone, step="linking")
                _log(job_id, "已匹配账号 " + phone + "，准备处理 PIN 并绑定链接")
                pin_prep = _ensure_pin_with_job(account, target_pin, job_id)
                if not pin_prep["ok"]:
                    skipped_phones.add(phone)
                    try:
                        _release_gopay_midtrans_binding(phone, message="Quick PIN 失败，账号已释放")
                    except Exception:
                        pass
                    _log(job_id, "账号 " + phone + " PIN 处理失败（" + str(pin_prep["error"])[:140] + "），换号重试（" + str(attempt) + "/" + str(QUICK_MAX_ACCOUNT_ATTEMPTS) + "）")
                    continue
                pin = pin_prep["pin"]
                _log(job_id, "PIN 就绪（" + (pin_prep.get("note") or "ok") + "）")
                use_proxy = _pick_proxy(proxies) or str(account.get("proxy") or "").strip()
                _set_job(job_id, step="payment")
                try:
                    pjob = payment.start(phone=phone, pin=pin, midtrans_url=url, proxy=use_proxy)
                except Exception as exc:
                    msg = _sanitize_public_error(exc)
                    if any(k in msg for k in ("已绑定", "不能重复使用", "已支付成功", "已有失败记录", "已经跑过或正在运行")):
                        try:
                            payment.reset_snap_for_retry(url)
                        except Exception:
                            pass
                    _fail_job(job_id, msg)
                    return
                pid = str((pjob or {}).get("id") or "")
                if not pid:
                    _fail_job(job_id, "支付任务未创建成功")
                    return
                with quick_jobs_lock:
                    if quick_jobs.get(job_id):
                        quick_jobs[job_id]["payment_job_id"] = pid
                        quick_jobs[job_id]["otp_target"] = "payment"
                result = _wait_underlying(pid, job_id, lambda jid: payment.get(jid) or {},
                                          payment.submit_otp, "支付", 600)
                if result.get("ok"):
                    _succeed_job(job_id)
                    return
                if result.get("cancelled"):
                    _set_job(job_id, status="cancelled", step="done", error="任务已取消")
                    return
                try:
                    _release_gopay_midtrans_binding(phone, message="Quick 任务失败，账号已释放")
                    payment.release_snap_link(url, reason="Quick 任务失败，链接已释放")
                except Exception:
                    pass
                _fail_job(job_id, result["error"])
                return
            finally:
                lock.release()
        _fail_job(job_id, "尝试 " + str(QUICK_MAX_ACCOUNT_ATTEMPTS) + " 个账号后仍无法完成 PIN 处理")
    except Exception as exc:
        _fail_job(job_id, _sanitize_public_error(exc))


def _run_worker(batch_id):
    while True:
        with quick_jobs_lock:
            job = next((j for j in quick_jobs.values()
                        if j.get("batch_id") == batch_id and j.get("status") == "queued"), None)
            if job is None:
                return
            job["status"] = "running"
            job["started_at"] = _now()
            job["updated_at"] = _now()
            job_id = job["id"]
        with _quick_slots:
            try:
                _run_quick_job(job_id)
            except Exception as exc:
                _fail_job(job_id, _sanitize_public_error(exc))
        _update_batch_counts(batch_id)


def _create_batch(links, cdk, thread_count, proxies, target_pin):
    batch_id = uuid.uuid4().hex[:12]
    jobs = []
    with quick_jobs_lock:
        for url in links:
            job_id = uuid.uuid4().hex[:12]
            quick_jobs[job_id] = {
                "id": job_id,
                "token": secrets.token_urlsafe(12),
                "batch_id": batch_id,
                "status": "queued",
                "step": "link",
                "url": url,
                "proxies": list(proxies),
                "target_pin": target_pin,
                "cdk": cdk,
                "cdk_consumed": False,
                "phone": "",
                "payment_job_id": "",
                "register_job_id": "",
                "pin_job_id": "",
                "otp_target": "",
                "error": "",
                "logs": [{"ts": _now(), "text": "任务已创建，等待执行"}],
                "created_at": _now(),
                "updated_at": _now(),
                "started_at": "",
                "finished_at": "",
            }
            jobs.append(dict(quick_jobs[job_id]))
        quick_batches[batch_id] = {
            "id": batch_id,
            "status": "running",
            "total": len(links),
            "finished": 0,
            "succeeded": 0,
            "failed": 0,
            "created_at": _now(),
        }
    for _ in range(min(thread_count, len(links))):
        threading.Thread(target=_run_worker, args=(batch_id,), daemon=True).start()
    return batch_id, jobs


# ================= HTTP =================
class Handler(BaseHTTPRequestHandler):
    def send_security_headers(self):
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)

    def send_json(self, code, data):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_security_headers()
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length < 0 or length > MAX_JSON_BODY_BYTES:
            raise RequestBodyTooLarge("request_too_large")
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return {}

    def admin_ok(self, data):
        token = str(data.get("token") or self.headers.get("X-Admin-Token") or "").strip()
        with _cdk_lock:
            stored = _load_cdk_store()["admin_token"]
        return bool(token) and secrets.compare_digest(token, stored)

    def is_loopback(self):
        return self.client_address[0] in {"127.0.0.1", "::1", "localhost"}

    def do_GET(self):
        try:
            path = self.path.split("?", 1)[0]
            query = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            if path == "/":
                raw = _page().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_security_headers()
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            if path == "/api/health":
                self.send_json(200, {"ok": True, "service": "gopay-quick-cdk",
                                     "cdk": _cdk_summary(), "max_workers": MAX_WORKERS})
                return
            if path == "/api/jobs":
                self.send_json(200, {"jobs": _list_public_jobs()})
                return
            if path == "/api/admin/token":
                if not self.is_loopback():
                    self.send_json(403, {"error": "仅本机可查看管理员令牌"})
                    return
                with _cdk_lock:
                    token = _load_cdk_store()["admin_token"]
                self.send_json(200, {"token": token})
                return
            if path == "/api/admin/cdk/list":
                data = {}
                if not self.admin_ok(data):
                    self.send_json(401, {"error": "管理员令牌无效"})
                    return
                with _cdk_lock:
                    store = _load_cdk_store()
                    keys = []
                    for k in store["keys"]:
                        row = dict(k)
                        row["used_by"] = str(row.get("used_by") or "")[:8]
                        keys.append(row)
                self.send_json(200, {"keys": keys, "summary": _cdk_summary_locked(store)})
                return
            if path.startswith("/api/jobs/"):
                rest = path[len("/api/jobs/"):].strip("/")
                job_id = unquote(rest)
                token = (query.get("token") or [""])[0]
                job = _get_job(job_id)
                if job is None:
                    self.send_json(404, {"error": "任务不存在"})
                    return
                if token and job.get("token") == token:
                    self.send_json(200, {"job": _public_job(job)})
                else:
                    slim = _public_job(job)
                    slim.pop("logs", None)
                    self.send_json(200, {"job": slim})
                return
            self.send_json(404, {"error": "not_found"})
        except Exception as exc:
            self.send_json(400, {"error": _sanitize_public_error(exc)})

    def do_POST(self):
        try:
            path = self.path.split("?", 1)[0]
            data = self.read_json()
            if path == "/api/cdk/verify":
                result = _verify_cdk(str(data.get("code") or ""))
                result["ok"] = True
                self.send_json(200, result)
                return
            if path == "/api/jobs/batch":
                links = _parse_midtrans_links(data.get("midtrans_urls"))
                cdk = str(data.get("cdk") or "").strip()
                if not cdk:
                    raise ValueError("请先填写 CDK")
                norm = _normalize_cdk(cdk)
                if not CDK_RE.match(norm):
                    raise ValueError("CDK 格式无效，应为 GQ-XXXX-XXXX-XXXX-XXXX")
                try:
                    _verify_cdk(norm)
                except Exception as exc:
                    raise ValueError("CDK 校验失败：" + str(exc)) from exc
                thread_count = max(1, min(MAX_WORKERS, int(data.get("thread_count") or 1)))
                proxies = _parse_proxy_list(data.get("proxy") or data.get("proxies") or "")
                target_pin = str(data.get("target_pin") or TARGET_PIN).strip()
                if not re.fullmatch(r"\d{6}", target_pin):
                    raise ValueError("统一 PIN 必须是 6 位数字")
                batch_id, jobs = _create_batch(links, norm, thread_count, proxies, target_pin)
                summary = _cdk_summary()
                self.send_json(201, {
                    "ok": True,
                    "batch_id": batch_id,
                    "cdk_remaining": summary["unused"],
                    "jobs": [_public_job(j) for j in jobs],
                    "raw_tokens": [{"id": j["id"], "token": j["token"]} for j in jobs],
                })
                return
            if path.startswith("/api/jobs/") and path.endswith("/otp"):
                job_id = unquote(path[len("/api/jobs/"):-len("/otp")].strip("/"))
                job = _get_job(job_id)
                if job is None:
                    self.send_json(404, {"error": "任务不存在"})
                    return
                if str(data.get("token") or "") != job.get("token"):
                    self.send_json(401, {"error": "任务令牌无效"})
                    return
                code = str(data.get("code") or "").strip()
                if not re.fullmatch(r"\d{4,6}", code):
                    raise ValueError("验证码应为 4-6 位数字")
                target = str(job.get("otp_target") or "")
                field = {"payment": "payment_job_id", "register": "register_job_id", "pin": "pin_job_id"}.get(target)
                uid = str((job.get(field) or "") if field else "")
                if not uid:
                    raise ValueError("当前任务没有等待验证码")
                if target == "payment":
                    payment.submit_otp(uid, code)
                elif target == "register":
                    register.submit_otp(uid, code)
                elif target == "pin":
                    pin_manager.submit_otp(uid, code)
                _log(job_id, "已提交人工验证码（已脱敏）")
                self.send_json(200, {"ok": True, "job": _public_job(_get_job(job_id))})
                return
            if path.startswith("/api/jobs/") and path.endswith("/cancel"):
                job_id = unquote(path[len("/api/jobs/"):-len("/cancel")].strip("/"))
                job = _get_job(job_id)
                if job is None:
                    self.send_json(404, {"error": "任务不存在"})
                    return
                if str(data.get("token") or "") != job.get("token"):
                    self.send_json(401, {"error": "任务令牌无效"})
                    return
                _cancel_job(job_id)
                self.send_json(200, {"ok": True, "job": _public_job(_get_job(job_id))})
                return
            if path == "/api/admin/cdk/generate":
                if not self.admin_ok(data):
                    self.send_json(401, {"error": "管理员令牌无效"})
                    return
                count = max(1, min(1000, int(data.get("count") or 1)))
                quota = max(1, min(10000, int(data.get("quota") or 1)))
                codes = _generate_cdk_codes(count)
                now = _now()
                with _cdk_lock:
                    store = _load_cdk_store()
                    existing = {str(k.get("code") or "").upper() for k in store["keys"]}
                    inserted = 0
                    for code in codes:
                        if code not in existing:
                            store["keys"].append({
                                "code": code, "status": "unused", "quota": quota,
                                "used_count": 0, "created_at": now, "used_at": "",
                                "used_by": "",
                            })
                            inserted += 1
                    _save_cdk_store(store)
                    summary = _cdk_summary_locked(store)
                self.send_json(201, {"ok": True, "inserted": inserted, "codes": codes,
                                     "summary": summary})
                return
            if path == "/api/admin/cdk/import":
                if not self.admin_ok(data):
                    self.send_json(401, {"error": "管理员令牌无效"})
                    return
                inserted = 0
                skipped = 0
                now = _now()
                with _cdk_lock:
                    store = _load_cdk_store()
                    existing = {str(k.get("code") or "").upper() for k in store["keys"]}
                    for line in str(data.get("text") or "").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        quota = 1
                        if "----" in line:
                            code_part, quota_part = line.split("----", 1)
                            code_part = code_part.strip()
                            try:
                                quota = max(1, int(quota_part.strip()))
                            except Exception:
                                quota = 1
                        else:
                            code_part = line
                        norm = _normalize_cdk(code_part)
                        if not CDK_RE.match(norm):
                            skipped += 1
                            continue
                        if norm in existing:
                            skipped += 1
                            continue
                        store["keys"].append({
                            "code": norm, "status": "unused", "quota": quota,
                            "used_count": 0, "created_at": now, "used_at": "",
                            "used_by": "",
                        })
                        existing.add(norm)
                        inserted += 1
                    _save_cdk_store(store)
                    summary = _cdk_summary_locked(store)
                self.send_json(201, {"ok": True, "inserted": inserted, "skipped": skipped,
                                     "summary": summary})
                return
            if path == "/api/admin/cdk/reset":
                if not self.admin_ok(data):
                    self.send_json(401, {"error": "管理员令牌无效"})
                    return
                codes = [str(x).strip() for x in (data.get("codes") or [])]
                reset_count = 0
                with _cdk_lock:
                    store = _load_cdk_store()
                    targets = {_normalize_cdk(c) for c in codes if c}
                    for k in store["keys"]:
                        if str(k.get("code") or "").upper() in targets:
                            k["status"] = "unused"
                            k["used_count"] = 0
                            k["used_at"] = ""
                            k["used_by"] = ""
                            reset_count += 1
                    _save_cdk_store(store)
                    summary = _cdk_summary_locked(store)
                self.send_json(200, {"ok": True, "reset": reset_count, "summary": summary})
                return
            self.send_json(404, {"error": "not_found"})
        except RequestBodyTooLarge:
            self.send_json(413, {"error": "request_too_large", "max_bytes": MAX_JSON_BODY_BYTES})
        except Exception as exc:
            self.send_json(400, {"error": _sanitize_public_error(exc)})

    def log_message(self, *_args):
        pass


def main():
    _start_quick_smsbower_screen_workers()
    with _cdk_lock:
        _load_cdk_store()
    print("=" * 60, flush=True)
    print("GoPay Quick CDK 服务启动", flush=True)
    print("地址: http://127.0.0.1:" + str(PORT) + "/", flush=True)
    print("管理员令牌已生成，请从本机管理页读取", flush=True)
    print("=" * 60, flush=True)
    host = os.environ.get("GOPAY_QUICK_HOST", "127.0.0.1").strip() or "127.0.0.1"
    ThreadingHTTPServer((host, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
