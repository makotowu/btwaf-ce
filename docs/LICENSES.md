# 许可证与合规说明

本项目以 **AGPL-3.0** 发布（`LICENSE`），与移植的 OWASP CRS（Apache-2.0）、libinjection（BSD-3）、PayloadsAllTheThings（MIT）、DOMPurify（Apache-2.0）兼容。

## 各来源义务

| 来源 | 义务 |
|---|---|
| OWASP CRS（Apache-2.0） | 保留版权/NOTICE、标注修改、附许可证全文；生成规则文件头已标注来源与版本 |
| libinjection（BSD-3） | 保留版权声明、许可证全文；若后续移植代码，需在文件头标注 "derived from libinjection (BSD-3)" |
| PayloadsAllTheThings（MIT） | 保留版权与许可声明；语料目录附 NOTICE |
| DOMPurify（Apache-2.0） | 同上 |
| aaWAF `Payload.md`（AGPL-3.0） | 仅作为测试语料使用并标注来源 |

## 禁止事项

- 不得从无许可证仓库（如 loveshell/ngx_lua_waf、starjun/openstar）复制代码；
- 不得引入 GPL-2.0 代码（与 AGPL-3.0 不兼容），例如 jxwaf；
- 不得把 CRS 规则宣称为原创；生成文件保留原始 ID 与来源；
- 不得移除 `THIRD_PARTY_NOTICES.md`、`licenses/` 与生成文件头的归属信息。

## 分发

构建出的发布 zip 包含 `THIRD_PARTY_NOTICES.md`、`licenses/`、`LICENSE`；测试语料与构建脚本不随安装包分发，但保留在源码仓库中。
