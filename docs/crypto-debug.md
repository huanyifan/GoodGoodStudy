# 加解密调试与日志说明

Rust 客户端支持 `--debug-config [https-url]`：使用当前用户 DPAPI 设备凭据请求真实接口，逐步输出脱敏 JSON 日志，成功后退出，不进入截图或发信循环。日常运行与 `--check-config` 不输出这些调试记录。

`--debug-crypto server/crypto_debug.py` 在本机通过进程管道把公开握手交给 Python，调用实际服务端 `make_response` 函数加密**合成配置**，再由 Rust 解密。此模式不读取真实服务器配置或访问凭据；没有模拟 HTTPS 或设备鉴权。

## 完整运行

~~~powershell
python -B .\tools\debug_crypto.py --exe C:\private\GoodGoodStudy.exe --output-dir C:\private\debug-logs
~~~

需要 Python 与 `server/requirements.txt` 中的密码学库。`python` 必须在 PATH 上。工具先执行本机双方互通，再访问真实 HTTPS 接口两次。`--offline-only` 只执行本机互通。日志文件与 JSON 汇总保存在指定目录；不要将运行日志提交仓库。

## 协议的实际步骤

1. Windows DPAPI 解开长期设备凭据，HTTPS POST 的 `Authorization: Bearer` 携带访问令牌。服务器校验令牌哈希并限制速率。TLS 校验系统信任证书，拒绝重定向。访问令牌用于鉴权，不是 AES 密钥。
2. 客户端生成一次性 P-256 私钥 `c`、公钥 `C=cG` 和 32 字节随机 `Nc`。提交协议版本、设备 ID、`C`、`Nc`。公钥编码为 65 字节 SEC1 非压缩点（04 || X || Y），再 Base64。
3. 服务器校验客户端曲线点，生成一次性私钥 `s`、公钥 `S=sG` 和 32 字节随机 `Ns`。服务器计算 `Z=ECDH(s,C)`；客户端之后计算 `Z=ECDH(c,S)`，二者得到相同共享秘密。双方先计算 `IKM=SHA256(Z)`，与原 Windows CNG 协议兼容。
4. 双方执行 HKDF-SHA256，输出 64 字节：`salt=Nc||Ns`（64 字节）；`info=UTF8(protocol+"|"+deviceId+"|")||C||S||Nc||Ns`。当前协议标识为 `GoodGoodStudy.Config.ECDH-P256.HKDF-SHA256.v2`。输出前 32 字节用于 AES，后 32 字节用于 HMAC。
5. 服务器将配置序列化为 UTF-8 JSON，执行 PKCS#7 填充（块大小 16 字节），生成随机 16 字节 IV，再执行 AES-256-CBC 加密。
6. 服务器计算 `tag=HMAC-SHA256(Kmac, prefix||IV||ciphertext)`，其中 `prefix=ASCII("GoodGoodStudy.Config.v1|AES-256-CBC+HMAC-SHA256|")`。响应携带服务端公钥、nonce、协议标识、IV、密文与 32 字节 tag；不携带私钥、共享秘密或会话密钥。
7. 客户端验证版本、算法、曲线点、nonce 和长度，使用本次临时私钥派生同样的两把密钥，先以常量时间方式验证 HMAC。只有验证通过才进行 AES 解密、PKCS#7 去填充、JSON 与配置范围校验。
8. 临时密钥不序列化；Rust 使用 Zeroizing 和密码学类型析构清理。Python 清理显式字节数组，库内部临时副本由 Python/OpenSSL 管理；这不等于保证清除操作系统换页或所有内存副本。

## 如何读日志

- `side=server` 是本机 Python 实际加密函数的记录；线上部分的 `side=client` 来自 Rust 对真实 HTTPS 响应的处理，不声称读取了线上服务器进程内存。
- 日志打印双方公钥、nonce、IV、HMAC、密文长度与摘要，以及 HKDF salt、info 布局／长度／摘要。双方公开参数完全匹配且 HMAC、解密成功，证明本次派生与加解密互通。
- 私钥、Z、IKM、两把派生密钥、访问令牌、邮箱地址、SMTP 密码和完整配置明文均不打印；不会为诊断额外记录这些秘密的指纹。
- 工具断言双方公钥、nonce、HKDF 公开输入和加密信封一致；篡改 MAC、IV、密文或服务器 nonce 必须被拒绝；旧响应交给另一个临时会话必须被拒绝。两次线上请求的双方公钥、nonce、IV、密文摘要必须变化。
- 跨会话重放检测依靠临时密钥和握手绑定；同一 Session 对象重复处理同一合法响应没有单独的已消费标记。生产获取流程每次创建新 Session，仅处理一次响应。

## 真实截图运行测试

显式运行 `powershell -NoProfile -ExecutionPolicy Bypass -File tools/Test-Runtime.ps1 -ExecutablePath C:\private\GoodGoodStudy.exe`，可测试正常运行入口，而非仅测试配置接口。需要已导入当前用户 DPAPI 设备凭据，且当前 HTTPS 配置为默认截图目录、120 秒间隔、批量大小至少 2。脚本先通过真实接口核对这些条件，不符合时拒绝启动测试。

脚本在当前用户私有构建目录创建独立测试数据目录，复制 DPAPI 密文凭据，仅为子进程覆盖 LOCALAPPDATA；正常后台运行程序，检查第二实例被拒绝，等待一张真实截图，发出正常停止事件，验证 PNG 可解码、退出码为 0、邮件队列为空。结果在该目录的 runtime-test.json、stdout.log、stderr.log 和 GoodGoodStudy/runtime.log 中；图片也保留在该私有目录。不会安装登录启动任务或等待累积到发送批次。

普通运行失败也会将脱敏静态原因写入 runtime.log；HTTPS 传输失败时，stderr 仅补充连接类别、超时标志和操作系统错误码，不输出请求头、令牌或完整网络异常对象。
