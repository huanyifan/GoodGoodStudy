# GoodGoodStudy

Windows 定时截图与邮件批次发送工具，基于 [Sanhom365/GoodGoodStudy](https://github.com/Sanhom365/GoodGoodStudy)，保留 GPL-3.0 许可证和原作者信息。主实现为原生 **Rust**，另提供独立 **Go** 实现；两者均无需 .NET。运行环境为 Windows 10/11 x64。

- Rust 源码：clients/rust；临时密钥使用 Zeroizing 和密码学类型的析构清理。
- Go 源码：clients/go；显式清理派生字节数组，内部密码学对象由 Go 运行时管理。
- 两份程序共用协议、DPAPI 设备凭据格式及 Windows 互斥锁，一次选择一份运行。
- 根目录 VB.NET 项目保留为迁移参考与协议互操作测试基线，不是原生发布包的运行依赖。

本版修复空路径、批次越界、ZIP 重名和资源释放问题，提供邮件失败队列、登录自启动与每分钟进程守护。配置采用 **设备鉴权 + HTTPS + 每次请求临时 ECDH 密钥协商 + AES-256-CBC/HMAC-SHA256**。

## 首次使用

1. 选择 Rust 或 Go 程序包，解压到固定的本地目录，保留 EXE 与 tools 目录。
2. 在实际运行截图程序的 Windows 用户下，将私下提供的设备凭据文件拖到包内 **Import-Profile.cmd**，或运行：

   ~~~powershell
   .\GoodGoodStudy.exe --import-profile C:\private\client-profile.json
   ~~~

   已有凭据时默认拒绝覆盖；明确替换使用 --import-profile <文件> --replace。凭据只授予配置访问权，不是会话加密密钥；不要上传网站或 GitHub。

3. 检查接口。此命令不截图、不发邮件：

   ~~~powershell
   .\GoodGoodStudy.exe --check-config
   ~~~

4. 手动运行 GoodGoodStudy.exe，或双击 **Enable-Autostart.cmd** 开启登录自启动和每分钟进程检查。启用后立即后台运行截图。

默认配置接口：

https://yifan.im/tools/goodgoodstudy/config.json

它是需要鉴权的 POST 接口，浏览器匿名 GET 返回 401，不提供静态公开配置。自定义地址可使用：

~~~powershell
.\GoodGoodStudy.exe --config-url https://example.com/tools/goodgoodstudy/config.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Autostart.ps1 -Mode Enable -ConfigUrl https://example.com/tools/goodgoodstudy/config.json
~~~

配置在启动时获取，更改后重启生效。请求只接受 HTTPS，校验系统 TLS 证书，拒绝重定向，整体超时 15 秒，响应最大 128 KiB。没有离线配置缓存；服务器不可达或凭据被撤销时，本次启动停止，守护任务会在后续分钟重试。

## 自启动与进程守护

- **Enable-Autostart.cmd**：先验证凭据与远端配置，再注册当前用户任务，立即启动；以后登录延迟 15 秒启动，每分钟检查进程。截图后台运行。
- **Disable-Autostart.cmd**：设置停用标记、移除任务，通知由守护工具启动的截图进程正常退出；最多等待 20 秒，超时再结束该进程。
- **Autostart-Status.cmd**：查看任务状态、当前会话是否运行及日志位置。

任务名为 GoodGoodStudy-Watchdog-<用户SID>，在任务计划程序中可见，使用当前用户交互令牌与最低权限。无需保存 Windows 登录密码，也不会注入 explorer.exe。截图需要用户已登录；锁屏等不可截图情况记录错误并继续等待。若电脑休眠，不会为截图唤醒；恢复后继续调度。

启用后单独关闭截图进程，会在下次分钟检查被重新拉起。需要暂停请使用停用工具。手动启动且未由守护记录的进程不自动结束。守护校验完整程序路径、PID、启动时间和会话，避免误结束 PID 复用后的其他进程。它检查进程是否存在，不判断进程内部是否卡死。

请在解压后的固定本地目录启用，移动目录前先停用。更新程序时先停用、替换文件，再重新启用。如系统策略禁止注册任务，可在同一 Windows 账号下以管理员权限运行工具；不要换另一个用户，否则其 DPAPI 凭据不同。工具会改变当前用户的任务计划，并在启用时开始实际截图与邮件发送。

## 临时密钥与设备鉴权

每次获取配置：

1. 客户端生成内存中的临时 P-256 ECDH 私钥、公钥和 32 字节随机 nonce；提交设备 ID、公钥、nonce，并在 HTTPS Authorization 中携带设备访问凭据。
2. 服务端验证凭据哈希，生成新的临时 ECDH 密钥和 nonce。
3. 双方计算 ECDH 共享秘密，先 SHA-256，再按 RFC 5869 HKDF-SHA256 派生本次 64 字节会话材料。HKDF salt 为双方 nonce 拼接；info 包含协议标识、设备 ID、双方公钥与 nonce。
4. 前 32 字节用于 AES-256-CBC，后 32 字节用于 HMAC-SHA256；随机 IV、PKCS7 填充，先认证再解密。响应只含公钥、nonce、IV、密文和 MAC。
5. 客户端解密并验证配置，清理派生数组、释放临时 CNG 密钥。应用不序列化或记录 ECDH 私钥、共享秘密或会话加密密钥；服务端同样不持久化它们。

算法名称、公钥和 IV 可以公开，不是解密密钥。TLS 仍负责服务器身份验证和访问凭据的传输保护。不能为了额外 ECDH 加密而跳过 TLS 证书校验。

设备凭据保存在 %LOCALAPPDATA%\GoodGoodStudy\device-profile.dpapi，由当前用户 DPAPI 保护；它是长期访问权限，持有者可以请求新配置，但不能直接解密以前捕获的独立会话。服务端只保存凭据 SHA-256 哈希。每台设备建议单独登记，以便单独撤销。

创建、导出与导入设备凭据：

~~~powershell
.\GoodGoodStudy.exe --create-profile C:\private\client-profile.json
.\GoodGoodStudy.exe --export-profile C:\private\another-copy.json
.\GoodGoodStudy.exe --import-profile C:\private\client-profile.json
~~~

导出文件以当前用户独占 ACL 创建。创建后必须在服务端登记才有访问权限。服务器管理员可在可信管理电脑使用：

~~~powershell
python -B .\server\config_admin.py --profile C:\private\client-profile.json --devices C:\private\devices.json
~~~

只上传生成的 devices.json，不上传原始客户端凭据。撤销设备时从服务器私有 devices.json 删除对应设备 ID。现有已运行进程直到重新获取配置前仍持有先前配置，因此需要立即停用时也应停止该设备程序。

本版不使用旧版 config-key.dpapi、client-import.key 或 *.encrypted.json 配置缓存；迁移成功后应移除旧文件。旧密文不作为回退来源。客户端不再提供创建/导入共享 AES 密钥的命令。

## 私有服务端与配置管理

源码的 server/Dockerfile 固定官方 Python 3.12 镜像摘要，依赖 cryptography==50.0.0。服务监听容器内 8093，经宿主 127.0.0.1:8093 接入 Caddy HTTPS 精确路由：

~~~
handle /tools/goodgoodstudy/config.json {
    request_body {
        max_size 8KB
    }
    reverse_proxy 127.0.0.1:8093
}
~~~

其他 tools 静态文件继续原方式服务。容器只读、无额外 capability、非 root UID、关闭 core dump，并设内存/PID/日志上限。数据只读挂载到 /data：

- config.json：真实配置，包括邮箱设置。放在非公开目录，文件权限 0400。
- devices.json：设备 ID 到访问凭据 SHA-256 哈希的映射，同样为私有文件。

服务端长期配置是私有文件；临时加密密钥不写盘。并发限制 16，每台已授权设备每分钟最多 60 次请求；请求体最大 4 KiB。日志不记录 Authorization、请求/响应正文或密钥。

使用无秘密的 config.example.json 作为格式模板。旧 INI 可在 Windows PowerShell 5.1 下转换：

~~~powershell
.\GoodGoodStudy.exe --convert-ini C:\private\config.ini C:\private\server-config.private.json
~~~

转换结果是仅当前用户可读的服务端私有明文配置，不是可公开上传的静态文件；只部署到上述私有目录。旧 timeInterval 按分钟转换为秒，每批 10 张，SMTP 使用 STARTTLS 587。如邮箱要求其他设置，请使用 JSON 配置调整。端口 465 的隐式 TLS 不受当前 SmtpClient 实现支持。

## 配置字段与运行行为

| 字段 | 默认值 | 含义 |
|---|---|---|
| intervalSeconds | 180 | 截图间隔，1–86400 秒，首次等待一个间隔 |
| batchSize | 10 | 每批 1–100 张，仅邮件模式组包 |
| screenshotDirectory | 空 | 自动创建当前用户本地应用数据 captures 目录；自定义为绝对路径 |
| retentionDays | 7 | 本地保存模式保留天数，1–365 |
| maxStorageMB | 512 | 截图前检查的收集暂停阈值，16–8192 MiB，可能多出一张图片或当前归档临时空间 |
| mail.enabled | false | 是否发信 |
| mail.host / port / enableSsl | 空 / 587 / true | SMTP STARTTLS，强制 TLS |
| mail.sender / recipient | 空 | 各一个发件人与收件人地址 |
| mail.username / password | 空 | SMTP 用户名与邮箱授权码 |

截图仅主屏，采用唯一文件名；完整 ZIP 落盘后才移除原图。独立线程处理持久待发送队列，失败保留 ZIP 并在 5–300 秒间重试。发送成功后删除 ZIP。超过 10 MiB 的压缩附件保留并跳过，需手动处理；邮件编码还会增加体积。SMTP 在服务端已接收后若连接中断，重试可能产生重复邮件。

邮件模式不自动删除未发送数据，达到容量阈值时暂停收集；本地保存模式按天数/容量清理。截图和 ZIP 是本地明文文件，不受配置会话加密保护。运行日志和守护日志位于 %LOCALAPPDATA%\GoodGoodStudy 并轮转。

## 编译与验证

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Build-Test.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Tests\Autostart.Tests.ps1 -ValidateWithScheduler
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Tests\Interop.Tests.ps1
~~~

原生构建与测试：

安装 Go、Rust MSVC 工具链、rustfmt/Clippy 和 Visual Studio C++ Build Tools 后，可运行：

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Build-Native.ps1
~~~

产物位于 artifacts/Rust 和 artifacts/Go；也可以使用下面的独立命令。

~~~powershell
cd clients/go
go test ./...
go vet ./...
go build -trimpath -ldflags "-s -w" -o bin/GoodGoodStudy.exe .

cd ../rust
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
~~~

Rust 构建使用 Windows MSVC 工具链和 Visual Studio C++ Build Tools；已验证 Rust 1.99.1 与 Go 1.26.5。锁文件固定依赖。上述 VB.NET 基线测试另需 Visual Studio Build Tools，Python 互操作测试需 cryptography。

回归只使用虚拟图片、一次性凭据和回环服务，不截图、不发邮件、不启用真实自启动任务。任务定义使用 Windows TASK_VALIDATE_ONLY 接口验证。真实配置、设备凭据、会话密钥和构建产物均不提交到仓库。应用不主动将会话密钥写盘；这不等于对操作系统换页、调试器或内存转储作保证。
