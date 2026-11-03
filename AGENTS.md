# GoodGoodStudy 项目约定

- Rust（clients/rust）是用户明确指定的主项目，后续功能默认在此实现。
- Go 是对照实现，VB.NET 是迁移参考；除非当前任务需要，不要求同步扩展三份实现。
- 安装目标为当前用户的 %LOCALAPPDATA%/Programs/GoodGoodStudy；数据位于 %LOCALAPPDATA%/GoodGoodStudy。
- 个人免导入安装包含设备访问凭据，只能生成在受当前用户 ACL 保护的私有目录，不提交到 Git、不上传公共下载地址。
- 源码和测试中不得保存真实配置、设备访问令牌或临时会话密钥。会话密钥仅在进程内存中使用。
- 安装测试优先用校验模式和隔离测试数据；不要默认启动本机实际截图或邮件发送。
- 自启动必须有可见任务与停用/卸载入口，不向 explorer.exe 注入线程。
