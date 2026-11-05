# Rust 邮件发送测试

真实发信测试使用当前 Windows 用户 DPAPI 设备凭据，通过正常 HTTPS/ECDH 路径取得配置，再调用生产代码共用的 MIME 构建和 SMTP 传输函数。测试邮件主题以 `[GoodGoodStudy SMTP TEST]` 开头，只附带含一份合成文字的 ZIP，不读取截图或历史发送队列。SMTP 返回成功仅证明服务器接收，不证明收件箱已投递或未进入垃圾箱。

在已明确需要发送测试邮件时，于 clients/rust 下运行：

~~~powershell
cargo test --locked --lib real_configured_smtp_test_mail -- --ignored --nocapture
~~~

该命令发送一次邮件到远端配置的收件人。`GGS_SMTP_TEST_PORT` 可仅为测试进程覆盖端口；不设置时完整沿用远端配置。默认 cargo test 会跳过真实发信测试。报告保存于 `%LOCALAPPDATA%\GoodGoodStudy\mail-tests\<测试ID>\mail-test.json`，只包含主题、端口、TLS模式、附件校验和SMTP状态，不保存密码或收发地址。合成 ZIP 留在独立测试目录，不进入日常待发队列。

MIME 会先经 Python 标准库独立解码，验证唯一附件为 ZIP、内部只有合成文本，之后才尝试真实发送。普通测试还运行本机421临时拒绝场景，执行真实发送工作线程并确认原ZIP及队列保留，日志不包含密码。

Rust 3.2.2 按端口选择TLS：465/994使用隐式TLS，其余端口使用必需STARTTLS，均校验证书。163邮箱本次实测587没有返回欢迎响应并超时，465完成TLS握手且测试邮件返回250。SMTP错误诊断只输出类别及状态码，不输出服务器原始响应或鉴权内容。
