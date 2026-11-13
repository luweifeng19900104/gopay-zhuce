gopay-zhuce

运行环境
Windows x64，Python 3.11 x64，需要联网安装 Python 依赖。
本包是源码分享版，不包含 Python 安装程序或离线依赖。

首次启动
1. 将整个 ZIP 解压到一个独立文件夹，不要在压缩包内部运行。
2. 在该文件夹打开 PowerShell 7，执行：
   py -3.11 -m pip install -r requirements.txt
3. 双击“启动.bat”或 start.bat。
4. 浏览器访问 http://127.0.0.1:19081/。
5. 在系统配置中填写自己的短信、代理和 CAPTCHA 配置，再导入自己的号码池。

仓库只提供 config/*.env.example 无密钥模板。首次启动会根据
config/runtime.env.example 创建 runtime.env；短信和 CAPTCHA 可在网页中配置，
也可以手工复制对应 example 文件。账号库、号码池和任务文件不会提交到 Git。
如端口 19081 被占用，请先关闭已经启动的同一服务。

本包使用当前服务的程序文件，包含先前的号码池短信 URL 绑定和 OTP 解析修改。
自动取码需要短信提供方确实返回有效验证码；测试通过不代表短信实际送达。
未发起真实注册、登录、付款或扣费测试。

分享包不含本机账号、PIN、短信 URL、API 密钥、任务记录、日志、浏览器资料、
设备分配记录或抓包样本。SDK 本机抓包模板留空，外部服务连通性需自行配置验证。
config/gopay_accounts.example.json 仅为结构示例，不是实际账号。

可选回归测试
py -3.11 -m pip install pytest
py -3.11 -m pytest -q

文件完整性
PACKAGE_MANIFEST.sha256 记录仓库发布文件的 SHA256。
程序运行后会写入账号和任务数据，不要把使用后的整个目录再次直接分享。
