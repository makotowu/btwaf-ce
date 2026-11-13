# 测试语料来源与许可（NOTICE）

> 本文件维护测试语料的来源、许可证与统计。第三方内容按各自许可证使用。

## 目录与许可

| 目录 | 来源 | 版本 | 许可 | 条数 |
|---|---|---|---|---:|
| `tests/corpus/crs/` | OWASP CRS 回归测试 tests/regression/tests（规则移植语料） | v4.30.0 | Apache-2.0 | 3260 |
| `tests/corpus/aaWAF/` | aaWAF 仓库 Payload.md（仅语料，未复制代码/规则） | - | AGPL-3.0 | 75 |
| `tests/corpus/libinjection/` | libinjection data/*.txt + false_positives.txt | v4.0.1 | BSD-3-Clause | 2190 |
| `tests/corpus/dompurify/` | DOMPurify test/fixtures（XSS 向量） | v3.4.17 | Apache-2.0 | 156 |
| `tests/corpus/pat/` | PayloadsAllTheThings（精选 SQLi/XSS/SSRF/Upload） | 4.2 | MIT | 2951 |
| `tests/corpus/benign/` | 本项目自建正常流量 | - | AGPL-3.0 | 137 |
| `tests/corpus/regressions/` | 本项目自建回归样例 | - | AGPL-3.0 | - |

合计：**8769** 条。

## 逐文件条数

| 文件 | 条数 |
|---|---:|
| `aaWAF/java.jsonl` | 34 |
| `aaWAF/php.jsonl` | 2 |
| `aaWAF/rce.jsonl` | 31 |
| `aaWAF/upload.jsonl` | 5 |
| `aaWAF/xss.jsonl` | 3 |
| `benign/self.jsonl` | 137 |
| `crs/java.jsonl` | 945 |
| `crs/lfi.jsonl` | 80 |
| `crs/php.jsonl` | 264 |
| `crs/protocol.jsonl` | 168 |
| `crs/rce.jsonl` | 895 |
| `crs/scan.jsonl` | 6 |
| `crs/sqli.jsonl` | 708 |
| `crs/xss.jsonl` | 194 |
| `dompurify/xss.jsonl` | 156 |
| `libinjection/false_positives.jsonl` | 434 |
| `libinjection/sqli.jsonl` | 1115 |
| `libinjection/xss.jsonl` | 641 |
| `pat/sqli.jsonl` | 1078 |
| `pat/ssrf.jsonl` | 200 |
| `pat/upload.jsonl` | 17 |
| `pat/xss.jsonl` | 1656 |

## 生成统计

- CRS：解析回归用例 3843 个，输出 3260 个（仅保留“已移植规则”的 expect_ids；跳过未移植规则 583、无 expect_ids 1032、重复/无效输入 140、策略偏差 1）。
- libinjection：恶意语料 1756 条；false_positives 全量 434 条（expect.block=false，其中 known_fp 8 条）。
- aaWAF：75 条；DOMPurify：156 条；PAT：2951 条；自建良性：137 条。

## 已知上游误报（known_fp）

对“CRS 上游规则语义正常命中、但业务上属已知误报”的个别样本，在 JSONL 行内标注
`"known_fp": true`（CRS 上游已知误报，不计入门禁，测试报告单列）。
**不删除样本、不排除规则**；处置建议：通过白名单或规则排除处理，不删除样本。

| 条数 | payload（截断） | 原因 |
|---:|---|---|
| 1 | `"CREATE A CRITTER"` | crs-942360：英文正文 SQL 关键字组合 |
| 1 | `18 CREATE GOLD` | crs-942360：英文正文 SQL 关键字组合 |
| 1 | `1; exec will create the case 7` | crs-932235：URL/正文被当命令注入 |
| 1 | `1;1;1;CONTROL;0;0;1;` | crs-932370：分号分隔文本被当 Windows 命令注入 |
| 1 | `LISTING-PRICE">                          P="L         TING-P` | crs-941160：HTML 片段/富文本被当 XSS |
| 1 | `O'connors UNION selected a few friendsf from` | crs-942270：英文正文 SQL 关键字组合 |
| 1 | `O'connors UNION selected a few friendsf from a` | crs-942270：英文正文 SQL 关键字组合 |
| 1 | `V1_OTHER_1"><IMG CLASS="SIZE-FULL WP-IMAGE-2764` | crs-941160：HTML 片段/富文本被当 XSS |

## 低分漏报口径

CRS 回归 YAML 的 `expect_ids` 断言“规则命中”，而单条 `score < 5` 的 WARNING/NOTICE 规则
在灵敏度 2（阈值 5）下不会触发 block（CRS 自身 anomaly 阈值同为 5）。
这类低分漏报保留在 block 检出分母中，作为产品真实漏报基线，
不标注 `low_score`、不做门禁排除（测试报告单列说明）。

## 构建期来源校验和（tools/vendor/MANIFEST.json）

| 来源 | 版本 | 归档 sha256 |
|---|---|---|
| coreruleset | 4.30.0 | `a4bb3688ef6205b64471a9ccbf0d7b024eb8edf39b97c6f6c0006e7a948f8550` |
| dompurify | 3.4.17 | `627162706444c5640bc016d18f4913cef809c6883b4cec7413e1a3bb55388eac` |
| libinjection | 4.0.1 | `1a7e7764615550bd70888f4a42c66bc7ecf001ca319b0d15a39cd18672db0be2` |
| payloadsallthethings | 4.2 | `638d0c6e007c0d42e72190cd99adf0e9900f8837fcbea8b72462f0e34094c08d` |

## 注意事项

- 语料仅用于测试与回归，运行期不读取 `tests/`；第三方语料保留原始来源与许可标注。
- aaWAF 语料来自其仓库 `Payload.md`（AGPL-3.0），未读取/复制 aaWAF 安装包内的 Lua/.so/规则 JSON。
- CRS 语料的 `expect.rule` 只指向已移植的规则 ID；未移植规则的用例已剔除。
- 外部 payload 统一以 `POST /` + `p=<urlencoded payload>` 注入，便于 ARGS/body 双通道扫描。
