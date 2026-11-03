# GoodGoodStudy

Windows 定时截图与邮件批次发送工具，基于 [Sanhom365/GoodGoodStudy](https://github.com/Sanhom365/GoodGoodStudy)，保留 GPL-3.0 许可证与原作者信息。

此版本修复空路径启动异常、批次越界、固定 ZIP 重名及资源未释放问题，加入 HTTPS 加密配置、本地密文缓存、待发送队列与重试。运行需要 **Windows 10/11、.NET Framework 4.8**，无需安装 .NET SDK。

## 首次使用

1. 将发布包解压至本地目录，保留 `GoodGoodStudy.exe` 和 `GoodGoodStudy.exe.config`。
2. 在目标电脑的实际运行用户下导入共享密钥：

   ```powershell
   .\GoodGoodStudy.exe --import-key C:\private\client-import.key
   ```

   也可以将密钥文件拖到发布包中的 `Import-Key.cmd` 上；只导入密钥，不会自动启动截图。

   导入文件只用于私下传递，导入成功后自行安全保管或删除。不要上传至网站、GitHub 或公共共享目录。已存在密钥时默认拒绝覆盖；明确更换使用 `--import-key <文件> --replace`。

3. 先检查远程配置。此命令不截图、不发邮件：

   ```powershell
   .\GoodGoodStudy.exe --check-config
   ```

4. 启动程序：

   ```powershell
   .\GoodGoodStudy.exe
   ```

   进程在控制台运行，按 Ctrl+C 退出；不会自行注册开机启动。默认地址是：

   `https://yifan.im/tools/goodgoodstudy/config.json`

   指定其他 HTTPS 地址：

   ```powershell
   .\GoodGoodStudy.exe --config-url https://example.com/tools/goodgoodstudy/config.json
   ```

配置在启动时读取，更改远端配置后重启程序生效。仅接受 HTTPS，验证系统 TLS 证书，不跟随重定向；下载限时 15 秒，密文最大 128 KiB。先校验 HMAC，再解密并验证参数；验证成功才原子更新缓存。网络失败或远端内容无效时，使用同一 URL 上次验证成功的密文缓存；没有有效缓存则停止启动。更换 URL 或密钥后，旧缓存不能混用。

## 生成密钥与发布配置

在配置管理电脑生成一次随机主密钥：

```powershell
.\GoodGoodStudy.exe --init-key
.\GoodGoodStudy.exe --export-key C:\private\client-import.key
```

随机密钥共 64 字节，前 32 字节用于 AES-256-CBC，后 32 字节用于 HMAC-SHA256；每次加密生成新的 16 字节 IV，使用 PKCS7 填充。HMAC 覆盖协议/算法标识、IV 与密文，解密前校验。导入导出两端必须使用同一密钥，不需要将密钥放到服务器。

本机密钥保存在 `%LOCALAPPDATA%\GoodGoodStudy\config-key.dpapi`，用当前 Windows 用户的 DPAPI 保护。它不能直接复制给另一台电脑或另一用户使用，应通过导入工具安装共享密钥。导出文件是 Base64 原始密钥，创建时限制为当前用户可访问；不要放到不支持 Windows ACL 的共享盘。持有共享密钥的电脑同时具备生成有效配置的能力，仅向授权电脑分发。

复制无敏感数据的 `config.example.json` 为私有 `config.plain.json`，填入参数后加密：

```powershell
.\GoodGoodStudy.exe --encrypt-config C:\private\config.plain.json C:\private\config.json
```

只上传加密后的 `config.json`。网站上的 JSON 仅包含 `version`、`algorithm`、`iv`、`ciphertext`、`mac`，不会出现明文邮箱、授权码或主密钥。服务器静态提供文件即可，不需要解密。

### 从旧版 config.ini 迁移

对包含 `senderMail`、`smtpServer`、`tokenCode`、`toMail`、`timeInterval` 的 INI，使用 **Windows PowerShell 5.1**：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Convert-Ini.ps1 -InputPath C:\private\config.ini -OutputPath C:\private\config.json -ExecutablePath .\GoodGoodStudy.exe
```

此工具在内存中转换并加密，不生成明文 JSON。旧版 `timeInterval` 按分钟转换为秒；每批 10 张；使用 SMTP STARTTLS 587、独立收件地址。如服务器要求其他设置，请使用 JSON 示例手动配置。原始 INI 仍包含秘密，工具不会擅自删除它。

## 明文配置字段

| 字段 | 默认值 | 说明 |
|---|---|---|
| intervalSeconds | 180 | 截图间隔，1–86400 秒；首次截图等待一个间隔 |
| batchSize | 10 | 每批 1–100 张，仅邮件模式组包 |
| screenshotDirectory | 空字符串 | 空值自动建立当前用户本地应用数据目录下的 captures；自定义路径必须为绝对路径 |
| retentionDays | 7 | 仅本地保存模式的图片保留天数，1–365 |
| maxStorageMB | 512 | 收集暂停阈值，16–8192 MiB；检查在截图前，可能多出一张图和正在构建的 ZIP |
| mail.enabled | false | 是否发送邮件 |
| mail.host / port | 空 / 587 | SMTP 主机、端口；使用 STARTTLS，不支持 465 隐式 TLS |
| mail.enableSsl | true | 发信时强制启用 TLS |
| mail.sender / recipient | 空 | 发件人、独立收件人，各一个地址 |
| mail.username / password | 空 | SMTP 用户名与邮箱授权码 |

程序仅截图主屏，图片名称包含 UTC 时间和随机标识。图片先完整写入再进入批次，满批后生成唯一 ZIP，ZIP 完成后才删除原图。Bitmap、Graphics、消息、SMTP 与附件句柄均及时释放。

邮件队列保存在 `%LOCALAPPDATA%\GoodGoodStudy\pending`。发送线程与截图调度分离；网络失败保留 ZIP，5–300 秒退避重试，重启后继续处理。仅发送成功后删除 ZIP。压缩后大于 10 MiB 的附件保留并跳过，日志提示手动处理；邮件本身的 Base64 编码还会增加传输体积。SMTP 接收后若连接超时，重试可能产生重复邮件，这是至少一次投递的限制。

本地模式按保留天数与容量清理旧图；邮件模式不自动删除未发送图片或 ZIP，达到容量阈值时暂停新截图，避免悄悄丢弃待发送数据。重启或退出时不足一批的截图留在磁盘，后续补足再组包。日志 `runtime.log` 轮转保存一份，避免记录配置正文、密码或 URL。

截图与 ZIP 本身是本地明文文件；配置加密仅保护远程配置。请使用有权限控制的本地用户目录。已验证的缓存允许断网运行，但不提供配置过期或防回放机制；撤销旧配置时需更换密钥或清理缓存。

## 开发与测试

使用 Visual Studio Build Tools 的 MSBuild、VB 编译器和 Windows PowerShell。项目通过 NuGet 固定引用 `Microsoft.NETFramework.ReferenceAssemblies.net48 1.0.3`，不依赖本机安装开发者目标包。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Build-Test.ps1
```

回归测试使用临时虚拟图片、加密数据和 DPAPI，**不实际截图或发邮件**。应用产物在 `bin\Release`。测试覆盖加密往返与随机 IV、篡改和错误密钥拒绝、配置边界、HTTPS 限制、按 URL 隔离的密文缓存与回退、连续满批归档、失败保留原图和 DPAPI 导入。

旧版 `My.Settings` 文件不再作为运行配置来源；`App.config` 只声明运行时。真实 INI、明文 JSON、密钥、密文配置与构建输出均不提交到仓库。
