# emsign-g3-fix · v2

[![checks](https://github.com/m16a4666/emsign-g3-fix/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/m16a4666/emsign-g3-fix/actions/workflows/shellcheck.yml)

Debian / Ubuntu 系统信任库修复工具。历史文件名 `fix-emsign-g3only.sh` 保留，方便已有下载链接继续使用；v2 的默认策略已更新为 **Mozilla NSS 3.131.1**，不再只是禁用 G3。

优先安装发行版的 `ca-certificates` 安全更新。本工具用于审计和临时调整系统信任库，支持检查、预览、修复、验证、备份与回滚。无需额外 Python 包，运行时不联网。

## 信任策略

| 根证书 | 默认模式 | `--strict` 严格模式 |
| --- | --- | --- |
| emSign ECC Root CA - G3 | 禁用 | 禁用 |
| emSign ECC Root CA - C3 | 禁用 | 禁用 |
| emSign Root CA - C1 | 禁用 | 禁用 |
| emSign Root CA - G1 | **保持管理员原有状态** | 禁用 |
| emSign Root TLS CA - G3（如已安装） | 保持原状，检测到时警告 | 禁用 |
| AAA Certificate Services / Comodo AAA Services root | 保持原状，检测到时警告 | 禁用 |

C1、C3 的移除属于 Mozilla 信任政策调整，**不代表其私钥已泄露**。默认模式不会重新启用任何已禁用的根，不要求旧根的源文件存在，也不会补回已由系统更新移除的条目。

**默认模式不等于完整切断本次事件的所有信任路径。** AAA 及独立的 TLS-G3 信任锚仍可能提供交叉签名路径；`--check` 的退出码只表示所选策略是否满足。严格模式额外禁用这些已知路径及 G1，可能让依赖相关根的正常服务连接失败。它不提供通用的中间 CA / SPKI 吊销机制，也不能保证覆盖未来发现的其他交叉签名路径。

策略依据（2026-10-22 核对）：

- [Mozilla NSS 3.131.1 发布公告](https://groups.google.com/a/mozilla.org/g/dev-tech-crypto/c/vSxZxnOMMvs)：移除 C1、C3、G3。
- [Mozilla 事件通告](https://www.openwall.com/lists/oss-security/2026/10/20/1)：列明 G3、TLS-G3、AAA 三条根路径及 SPKI SHA-256；根移除有兼容性影响。
- [Debian DSA-6572-1](https://lists.debian.org/debian-security-announce/2026/msg00487.html)：通过安全更新移除 G3 和 Comodo AAA Services root。
- [Mozilla Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)：中间 CA 私钥泄露事件。

## 下载与运行

要求：Debian / Ubuntu 或使用相同 `ca-certificates.conf`、`update-ca-certificates` 机制的 Linux，Bash、Python **3.8+**。检查和预览无需 root；应用和回滚需要 root。

```bash
curl -fL --proto '=https' --tlsv1.2 \
  -o fix-emsign-g3only.sh \
  https://raw.githubusercontent.com/m16a4666/emsign-g3-fix/main/fix-emsign-g3only.sh
less fix-emsign-g3only.sh

# 只检查：0 = 满足所选策略；1 = 需要变更；2/3 = 错误
bash fix-emsign-g3only.sh --check

# 预览配置变更；不写文件、不创建备份、不运行更新器
bash fix-emsign-g3only.sh --dry-run

# 默认：禁用 C1/C3/G3，保持 G1 原状态
sudo bash fix-emsign-g3only.sh

# 严格：额外禁用 G1、独立 TLS-G3 和 AAA；先预览兼容性影响
bash fix-emsign-g3only.sh --strict --dry-run
sudo bash fix-emsign-g3only.sh --strict
bash fix-emsign-g3only.sh --strict --check
```

生产环境可把下载 URL 中的 `main` 替换为已审核的完整 commit SHA，固定脚本内容。`--verify` 是 `--check` 的别名。其他选项：`--backup-dir DIR`、`--version`、`--help`。

## 实现与验证

- 只把已有的目标配置条目标记为 `!`；修正重复 `!`、重复条目、缩进及 CRLF，不修改其他策略。
- 同时识别标准文件名和证书内容。G3、TLS-G3、AAA 按 SHA-256 SPKI 识别，C1/C3/G1 按证书 SHA-256 识别，改名的同一证书也能被发现。
- 检查实际 `/etc/ssl/certs/ca-certificates.crt` 与目录中的证书内容，包括 hash 链接，避免只看 `.pem` 文件名而漏检。
- 发现 `/usr/local/share/ca-certificates` 中的目标信任覆盖时，**写入前报错**并要求管理员先处理该本地覆盖，不擅自删除本地证书。
- 原子替换配置，保留权限和属主；应用操作使用进程锁；更新命令或后置验证失败时恢复原配置并尝试重新生成信任库，始终返回错误。
- 策略已满足时不重写配置、不重建 bundle、不新建备份。配置正确而 bundle 仍残留目标证书时，会重建并验证。

退出码：`0` 所选策略已满足 / 应用或回滚成功；`1` 检查或预览发现需要变更；`2` I/O、验证、依赖或更新错误；`3` 不支持的平台或找不到 Python 3。参数错误为 `2`。输出中的 AAA/TLS-G3 警告不会把默认模式的策略检查变成严格模式。

## 备份与回滚

首次需要变更时创建权限为 `0700` 的唯一备份目录，例如：

```text
/var/backups/emsign-trust-fix/emsign-xxxxxxxx/
  etc/ca-certificates.conf
  etc/ssl/certs/ca-certificates.crt
```

备份失败即停止，避免未备份先修改。脚本打印本次备份目录和可执行的回滚命令：

```bash
sudo bash fix-emsign-g3only.sh --rollback \
  /var/backups/emsign-trust-fix/emsign-xxxxxxxx
```

回滚会先备份当前配置，再恢复原始 `ca-certificates.conf` 到正确路径，使用当前已安装的证书源重新生成 bundle 和 hash 链接。bundle 备份用于审计，**不会错误地复制到 `/etc/` 或直接覆盖生成结果**。回滚会重新启用旧策略允许的信任；它只恢复配置，不会重新安装被系统更新删除的根证书，也不能撤销其他软件的证书源、hook 或信任库改动。回滚期间更新失败会尝试恢复回滚前配置；自动恢复也失败时会明确报告备份位置，需要手动修复。

## 范围

仅修改 Debian/Ubuntu 的系统 CA 配置，并调用系统更新器。Windows、macOS、RHEL/p11-kit 等平台会拒绝执行。独立的 certifi、虚拟环境、Java、Node.js、容器、浏览器和应用自带 CA 库需要分别更新；本工具不自动升级 pip 包，不声称已修复这些独立存储。更新器的系统 hooks 仍会按发行版配置运行。

本工具没有为系统添加永久的中间证书拒绝列表；将来重新安装证书、修改配置或增加本地信任覆盖后，应重新检查。操作期间避免同时运行包管理器或其他证书配置工具。

## 测试

```bash
bash -n fix-emsign-g3only.sh
shellcheck -S warning fix-emsign-g3only.sh
python3 -m unittest discover -s tests -v
```

离线单元测试使用历史 certifi 中的公开根证书，在临时目录测试，不碰宿主机信任库。CI 还在一次性 Debian 12 / Ubuntu 24.04 容器中验证真实 `update-ca-certificates`、严格模式、重复执行和回滚；Python 单元测试覆盖 3.8 / 3.12 / 3.14。

## English

This standalone Bash script embeds a Python standard-library implementation for Debian/Ubuntu system trust stores. Default policy disables the NSS 3.131.1 removals (G3, C1, C3) while preserving G1's existing state. It never re-enables roots or inserts missing configuration entries. `--strict` additionally disables G1 and the known AAA/TLS-G3 cross-signing roots, with potential compatibility impact.

Use `--check` / `--verify` to audit, `--dry-run` to preview, no options to apply, and `--rollback BACKUP` to restore configuration and regenerate the system store. Exit 0 means the selected policy is satisfied, not universal protection across applications or all possible certificate chains. Read the scope and rollback limitations above before use.

## License

[MIT](LICENSE). Public certificate test fixtures retain their original certificate data; see [fixture provenance](tests/fixtures/README.md).
