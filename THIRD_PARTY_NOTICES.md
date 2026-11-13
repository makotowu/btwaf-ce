# 第三方组件与内容声明（THIRD-PARTY NOTICES）

本项目以 **AGPL-3.0** 发布（见 `LICENSE`）。以下第三方内容按各自许可证使用，特此声明：

| 来源 | 许可证 | 使用方式 | 许可证全文 |
|---|---|---|---|
| [OWASP Core Rule Set (CRS)](https://github.com/coreruleset/coreruleset) | Apache-2.0 | 构建期从 OWASP CRS 将部分 SecRule 规则移植为 `lua/rules/crs/*.lua`；保留原始规则 ID（`crs-<id>`）、规则名与 `origin` 标注 | `licenses/Apache-2.0.txt` |
| [libinjection](https://github.com/client9/libinjection) | BSD-3-Clause | 测试语料（`tests/corpus/libinjection/`）；SQL/XSS 语义检测思路参考（未直接复制 C 源码） | `licenses/BSD-3-Clause.txt` |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | MIT | 测试语料（`tests/corpus/pat/`，精选） | `licenses/MIT.txt` |
| [DOMPurify](https://github.com/cure53/DOMPurify) | Apache-2.0 | 测试语料（`tests/corpus/dompurify/`，XSS 绕过向量） | `licenses/Apache-2.0.txt` |
| [aaWAF / BT-WAF](https://github.com/aaPanel/aaWAF) | AGPL-3.0 | 仅使用仓库内 `Payload.md` 作为测试语料（`tests/corpus/aaWAF/`）；仅参考设计思想，未使用其安装包中的 Lua/.so/规则 | 与本项目相同（AGPL-3.0） |
| Vue 3 / Element Plus | MIT | 前端运行时（`static/vendor/`，Vue 3 / Element Plus 官方 MIT 版本） | `licenses/MIT.txt` |

## 规则文件归属

`lua/rules/crs/*.lua` 为**生成文件**，由 `tools/import_crs.py` 从指定版本的 OWASP CRS 生成：

- 文件头包含 `origin=OWASP CRS vX.Y.Z` 与 Apache-2.0 声明；
- 每条规则保留 `id="crs-<原始 id>"`、`msg`、`tags`；
- 修改过的文件在文件头标注"移植"；
- 具体版本与生成信息见 `lua/rules/crs_meta.lua` 与 `lua/rules/index.json`。

## 测试语料归属

`tests/corpus/` 下每个目录均有 `NOTICE.md` 或目录级说明，标注来源、许可证与条数。测试语料不随插件安装包分发。测试依赖 wasmoon、vscode-oniguruma 为 MIT。

## 商标

"宝塔"、"堡塔"、"BT" 等商标归广东堡塔安全技术有限公司所有。本项目为社区第三方插件，与宝塔官方无隶属关系；插件名称与图标不使用官方商标。
