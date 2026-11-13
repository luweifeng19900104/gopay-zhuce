# gopay-zhuce

GoPay 协议注册、登录、账号池、支付和手机号换绑的本地控制服务。项目以 Python 实现，提供浏览器管理界面、短信接口接入、代理路由、CAPTCHA 配置以及协议回归测试。

## 主要功能

- GoPay 注册与已有账号登录
- 账号池、PIN 状态与 token 管理
- 协议支付与支付任务管理
- SMSBower 等短信接口接入
- 印尼代理服务商配置与用途绑定
- GoPay 2.16.1 / 2.22.1 版本化 native signer 接口
- 手机号换绑状态机与自动重登支持
- CAPTCHA provider 配置
- 协议、代理、安全加固和回归测试

## 环境

- Python 3.11 x64
- Windows 10/11 或 Linux
- 能访问所需上游服务的网络与代理

## 快速启动

Windows PowerShell：

```powershell
py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item config\runtime.env.example config\runtime.env
.\启动.bat
```

浏览器访问：

```text
http://127.0.0.1:19081/
```

Linux：

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp config/runtime.env.example config/runtime.env
PYTHONPATH=app/src .venv/bin/python -m gopay.server
```

## 配置

仓库仅提交无密钥模板：

- `config/runtime.env.example`
- `config/sms.env.example`
- `config/captcha.env.example`
- `config/gopay_accounts.example.json`

真实账号、token、PIN、手机号、短信 URL、API key、代理密码、任务记录和认证环境日志均被 `.gitignore` 排除。不要使用 `git add -f` 强制提交这些文件。

## Native Signer

`gopay_native_signer.py` 支持按 App 版本加载对应 native library。原始应用的 `.so` 文件不在本仓库中分发，需要在自己的授权测试环境中准备，并通过环境变量配置：

```text
OPAI_GOPAY_NATIVE_SIGNER=1
OPAI_GOPAY_NATIVE_VERSION=2.16.1
OPAI_GOPAY_NATIVE_LIBRARY=/path/to/libbatteryOpt-2161-x86_64.so
OPAI_GOPAY_NATIVE_SHIM=/path/to/android_shim.so
OPAI_GOPAY_NATIVE_LIBDIR=/path/to/compat-libs
```

版本专用路径可使用 `_2221` 等后缀，例如 `OPAI_GOPAY_NATIVE_LIBRARY_2221`。

## 测试

```powershell
py -3.11 -m pip install pytest
py -3.11 -m pytest -q
```

当前本地回归结果：`119 passed`。

## 仓库结构

```text
app/src/opai/core/   协议、支付、短信、代理和 signer 实现
gopay/               主控制服务与 Web UI
gopayquick/          精简入口
config/              无密钥模板与本地运行配置
tests/               回归测试
```

## 使用范围

仅在你拥有或明确获准测试的账号、设备和网络环境中使用。运行真实注册、登录、支付或换绑前，应先核对配置、代理出口及上游服务规则。
