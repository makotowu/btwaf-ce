# 宝塔WAF社区版（btwaf_ce）

## 0. 这个项目能做什么

在宝塔面板已有的 Nginx 站点上，以 OpenResty/Lua 内联执行应用层 WAF，不改变站点架构、不额外监听端口、运行期不依赖外网。

它能做：

- 检测并拦截常见 Web 攻击：SQL 注入、XSS、命令执行、文件包含/目录遍历、PHP/Java 代码注入、恶意上传、敏感文件探测、扫描器、恶意爬虫、协议异常、CC；
- 在面板内查看概览、拦截记录、封锁记录，按站点开关防护、配置灵敏度、黑白名单、规则库/排除和自定义规则；
- 先以观察模式运行、根据拦截记录调整白名单/规则，再切换为拦截模式；
- 安装/卸载时自动处理 Nginx Lua 处理链冲突，卸载时按安装清单恢复安装前配置。

它**不修复**应用本身的漏洞，也不能替代代码审计、补丁、权限控制和账号安全。

## 1. 社区版声明

这是**社区项目**，与宝塔官方（含其关联公司）**没有任何隶属、合作或背书关系**，不代表官方产品。插件名称、图标和文档仅用于说明这是一个面向宝塔面板的第三方社区插件；“宝塔”“堡塔”“BT”等商标归其权利人所有。

## 2. 项目状态与免责声明

- 这是一个**新项目，仍在成长**，接口、规则、配置和界面都可能调整；
- **不对拦截率、零误报、稳定性或任何安全效果作承诺**；
- **不建议在生产环境使用**，请先在测试站点验证，并自行做好备份、监控和回滚准备；
- 使用本项目即表示你理解并自行承担相关风险；请遵守 AGPL-3.0 和当地法律法规，只对自己有权测试的站点使用。

## 3. 问题与贡献

欢迎通过 Issue 反馈问题、提出建议，也欢迎提交 PR 一起完善项目。提交前请阅读 [贡献指南](CONTRIBUTING.md)。提交问题时请尽量附上：

- 面板版本、PHP/Python 版本、Nginx 版本与 `lua-nginx-module` 情况；
- 复现步骤、期望结果、实际结果；
- 相关配置（请先脱敏）和日志片段。

安全漏洞请不要公开提交 issue，按 [SECURITY.md](SECURITY.md) 的私密渠道报告。

## 4. 致谢

感谢这些社区开源项目和它们的维护者：

- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)（Apache-2.0）
- [libinjection](https://github.com/client9/libinjection)（BSD-3-Clause）
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)（MIT）
- [DOMPurify](https://github.com/cure53/DOMPurify)（Apache-2.0）
- [aaWAF](https://github.com/aaPanel/aaWAF) 的公开 Payload 语料（AGPL-3.0，仅测试语料）
- Vue 3、Element Plus、wasmoon、vscode-oniguruma 等前端/测试生态项目

具体许可证和归属见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 与 `licenses/`。

## 安装（从 Releases）

1. 打开项目的 **Releases** 页面，下载最新的版本 zip 包；
2. 宝塔面板 → 软件商店 → 第三方应用 → **导入插件**，上传该 zip；
3. 安装完成后打开插件，按“系统诊断”提示完成站点同步和防护配置。

安装脚本会自动检测 Nginx Lua 处理链冲突，备份并处理冲突项；卸载时恢复安装前配置。安装前建议自行备份 Nginx 配置和站点数据。

## 环境要求

| 项 | 要求 |
|---|---|
| 面板 | 宝塔 Linux 面板 9.x / 11.x / 13.x（Python 3.7+ 语法兼容） |
| Web 服务器 | Nginx 1.22+，需带 `lua-nginx-module`；或 OpenResty |
| 磁盘 | 约 10MB（含规则；日志随保留天数增长） |
| 网络 | 安装后运行不需要外网 |

```bash
/www/server/nginx/sbin/nginx -V 2>&1 | grep -i lua_nginx_module
```

## 首次使用

1. 安装后进入插件 → 系统诊断，确认环境正常；
2. 站点防护 → 同步站点；
3. 先开启观察模式，运行一段时间，检查误报；
4. 将误报 URL/参数加入白名单或规则排除；
5. 关闭观察模式，按站点开启防护；需要更严格时调整灵敏度。

## 卸载

推荐在宝塔面板中卸载插件。面板会调用插件自带的卸载流程，按安装清单恢复 Nginx 配置，并清理图标、数据、日志和配置。

旧版本没有安装清单时，无法还原更早的未知冲突，卸载过程会提示。

## 开发

安装方式只推荐 Releases。以下仅用于开发/测试：

```bash
git clone https://github.com/makotowu/btwaf-ce btwaf-ce && cd btwaf-ce
node tests/run.mjs
python tests/python/test_backend.py
python tools/check_frontend.py
python tools/check_rules.py
python tools/build_zip.py --version 0.1.0
```

## 安全、贡献与行为准则

- [SECURITY.md](SECURITY.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## 许可

本项目以 **AGPL-3.0** 发布，见 [LICENSE](LICENSE)。
