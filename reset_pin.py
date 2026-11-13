#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GoPay 独立重置 / 设置 PIN 脚本
==============================

复用 19081 项目的 opai 协议库（gojek_client + payment_inbox._PinManager），
把「重置/设置 PIN」从网页服务里抽成可单独运行的文件。

前置条件
--------
1. 目标手机号必须已存在于本机账号库 config/gopay_accounts.json
   （含 access_token / refresh_token / 设备信息），否则无法直接走协议。
2. 新 PIN 必须为 6 位数字。
3. forgot / setup 模式需要收到短信 OTP：
   - 账号带可用的 SMSBower activation_id 时自动接码；
   - 否则单账号模式会提示手动输入验证码。

用法示例
--------
# 已知旧 PIN，直接改成新 PIN
python reset_pin.py --phone 085123456789 --new-pin 147258 --mode known --old-pin 123456

# 忘记 PIN，走短信 OTP 重置
python reset_pin.py --phone 085123456789 --new-pin 147258 --mode forgot

# 账号没设置过 PIN，用短信 OTP 设置
python reset_pin.py --phone 085123456789 --new-pin 147258 --mode setup

# 批量（每行一个手机号，依赖 SMSBower 自动接码）
python reset_pin.py --phones-file phones.txt --new-pin 147258 --mode forgot --workers 3

# 指定 SMS 配置与账号库
python reset_pin.py --phone 085123456789 --new-pin 147258 --mode forgot --sms-env config/sms.env --accounts config/gopay_worker_accounts.json
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "app" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
# 不管从哪个目录启动，都切到脚本所在目录，保证 config/ 相对路径可解析。
os.chdir(ROOT)

# 第三方依赖检查：opai 协议库依赖 tls_client。
try:
    import tls_client  # noqa: F401
except ImportError:
    raise SystemExit(
        "缺少依赖 tls_client，请先安装：python -m pip install tls_client"
    )

TERMINAL = {"success", "failed", "cancelled", "canceled", "done", "error"}
OTP_MODES = {"forgot", "setup"}


def _load_sms_env(path: str) -> None:
    from opai.core.sms_helpers import load_selected_env_file

    load_selected_env_file(("OPAI_SMSBOWER_", "OPAI_HEROSMS_"), path=path)


def _normalize_phone(value: str) -> str:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if not digits:
        raise ValueError(f"无效手机号: {value}")
    if digits.startswith("0"):
        digits = "62" + digits[1:]
    elif not digits.startswith("62"):
        digits = "62" + digits
    if len(digits) < 10:
        raise ValueError(f"手机号格式错误: {value}")
    return "+" + digits


def collect_phones(args) -> list[str]:
    phones: list[str] = []
    if args.phone:
        phones.append(_normalize_phone(args.phone))
    if args.phones:
        for part in re.split(r"[\s,;，；]+", args.phones):
            if part.strip():
                phones.append(_normalize_phone(part))
    if args.phones_file:
        p = Path(args.phones_file).expanduser()
        for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            phone = line.split("----", 1)[0].strip()
            if phone:
                phones.append(_normalize_phone(phone))
    seen: set[str] = set()
    out: list[str] = []
    for phone in phones:
        if phone not in seen:
            seen.add(phone)
            out.append(phone)
    return out


def start_reset(phone: str, args, interactive_otp: bool) -> dict:
    from opai.core.payment_inbox import _PinManager, _find_gopay_account

    account, _idx = _find_gopay_account(phone)
    if account is None:
        return {"phone": phone, "status": "failed", "message": f"账号不存在于本机账号库: {phone}", "logs": []}

    mode = args.mode or "known"
    pm = _PinManager()
    try:
        job = pm.start(phone=account.get("phone", phone), old_pin=args.old_pin or "", new_pin=args.new_pin, mode=mode)
    except Exception as exc:
        return {"phone": phone, "status": "failed", "message": str(exc), "logs": []}

    job_id = job.get("id") or ""
    deadline = time.time() + max(30, args.timeout)
    otp_prompted = False
    while time.time() < deadline:
        current = pm.get(job_id) if job_id else None
        if current is None:
            return {"phone": phone, "status": "failed", "message": "任务不存在或已被清理", "logs": []}
        status = current.get("status") or ""
        if status in TERMINAL:
            return current
        if status == "waiting_otp" and not otp_prompted:
            otp_prompted = True
            code = (args.otp or "").strip()
            if not code and interactive_otp:
                try:
                    code = input(f"[{phone}] 请输入短信验证码（4-6 位数字）: ").strip()
                except (EOFError, OSError):
                    code = ""
            if code:
                pm.submit_otp(job_id, code)
            elif not interactive_otp:
                return {
                    "phone": phone,
                    "status": "failed",
                    "message": "等待短信验证码（SMSBower 自动接码不可用）；多并发模式请使用可自动接码的账号，或单账号模式手动输入",
                    "logs": current.get("logs") or [],
                }
        time.sleep(1)
    tail_logs = (pm.get(job_id) or {}).get("logs") or [] if job_id else []
    return {"phone": phone, "status": "timeout", "message": f"等待超时（>{args.timeout}s）", "logs": tail_logs}


def print_job(job: dict, verbose: bool) -> None:
    phone = job.get("phone") or job.get("local") or "-"
    status = job.get("status") or "unknown"
    message = job.get("message") or ""
    print(f"[{phone}] {status}: {message}", flush=True)
    if verbose and job.get("logs"):
        for item in job.get("logs") or []:
            at = str(item.get("at") or "")[:19]
            print(f"    {at} {item.get('message') or ''}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="GoPay 独立重置 / 设置 PIN")
    parser.add_argument("--phone", help="单个手机号")
    parser.add_argument("--phones", help="多个手机号，逗号/空格/换行分隔")
    parser.add_argument("--phones-file", help="手机号文件，每行一个（支持 手机号----其它 格式）")
    parser.add_argument("--new-pin", required=True, help="新 PIN（6 位数字）")
    parser.add_argument("--mode", choices=["known", "forgot", "setup"], default="known",
                        help="known=旧PIN修改; forgot=忘记PIN走短信OTP; setup=未设置PIN用OTP设置")
    parser.add_argument("--old-pin", default="", help="known 模式的旧 PIN")
    parser.add_argument("--otp", default="", help="短信验证码（留空则在单账号模式提示输入）")
    parser.add_argument("--sms-env", default="", help="SMS 配置文件路径（默认 config/sms.env）")
    parser.add_argument("--accounts", default="", help="账号库 json 路径（默认 OPAI_GOPAY_ACCOUNTS_FILE 或 config/gopay_worker_accounts.json）")
    parser.add_argument("--workers", type=int, default=1, help="并发数量（批量时）")
    parser.add_argument("--timeout", type=int, default=600, help="单个任务超时秒数")
    parser.add_argument("--verbose", action="store_true", help="打印完整任务日志")
    args = parser.parse_args()

    if args.accounts:
        os.environ["OPAI_GOPAY_ACCOUNTS_FILE"] = str(Path(args.accounts).expanduser().resolve())
    if args.sms_env:
        os.environ["OPAI_GOPAY_SMS_ENV_FILE"] = str(Path(args.sms_env).expanduser().resolve())
    if not args.sms_env:
        args.sms_env = os.environ.get("OPAI_GOPAY_SMS_ENV_FILE", "")

    _load_sms_env(args.sms_env)

    phones = collect_phones(args)
    if not phones:
        parser.error("请至少提供一个手机号（--phone / --phones / --phones-file）")

    interactive_otp = args.workers <= 1 and len(phones) == 1 and args.mode in OTP_MODES
    results: list[dict] = []
    if args.workers <= 1 or len(phones) == 1:
        for phone in phones:
            job = start_reset(phone, args, interactive_otp)
            results.append(job)
            print_job(job, args.verbose)
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(start_reset, phone, args, False): phone for phone in phones}
            for fut in as_completed(futures):
                job = fut.result()
                results.append(job)
                print_job(job, args.verbose)

    failed = [j for j in results if j.get("status") != "success"]
    print(f"\n完成 {len(results)}/{len(phones)}，成功 {len(results) - len(failed)}，失败 {len(failed)}", flush=True)
    for j in failed:
        print(f"  [{j.get('phone') or '-'}] {j.get('status')}: {j.get('message') or ''}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
