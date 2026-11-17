# ssh-certificate-authority-validator
Python OpenSSH 证书链校验库，处理主体、扩展、CA 信任和撤销边界

## 特性

纯 Python 实现的 OpenSSH 证书（`*-cert-v01@openssh.com`）解析与 CA 校验库，
只依赖 [`cryptography`](https://cryptography.io/)。库将「密码学验签」与
「授权策略」分离，避免把证书解析通过误当成认证通过。

- 解析证书 blob 的全部字段：nonce、公钥、serial、证书类型、key ID、
  principals、有效区间（valid after / valid before）、critical options、
  extensions、reserved、签名 CA 公钥与签名区。
  Principal 采用**精确匹配**，不做任何前缀匹配，杜绝 `alice` 被
  `alice-admin` 之类的身份混淆绕过；空 principal 列表按 OpenSSH 语义表示通配。
- 通过可注入的 CA verifier 校验签名，信任基于 CA 公钥 blob 的**精确比对**。
- 完整策略检查：证书类型（用户/主机）、短 nonce、撤销序列（serial、区间、
  key ID）、`source-address`、`force-command` 组合以及过期边界。

## 支持的证书类型

| 证书 key 类型 | 主体公钥 |
| --- | --- |
| `ssh-rsa-cert-v01@openssh.com` | RSA |
| `ssh-ed25519-cert-v01@openssh.com` | Ed25519 |
| `ecdsa-sha2-nistp256-cert-v01@openssh.com` | ECDSA P-256 |
| `ecdsa-sha2-nistp384-cert-v01@openssh.com` | ECDSA P-384 |
| `ecdsa-sha2-nistp521-cert-v01@openssh.com` | ECDSA P-521 |

证书内的 `type` 字段区分用户证书（`SSH_CERT_TYPE_USER=1`）与主机证书
（`SSH_CERT_TYPE_HOST=2`），主机连接必须出示主机证书、用户连接必须出示用户证书。

## 支持的签名算法

| CA 密钥 | 接受的签名算法 |
| --- | --- |
| Ed25519 | `ssh-ed25519` |
| RSA | `rsa-sha2-512`、`rsa-sha2-256`、`ssh-rsa`（SHA-1，仅兼容旧证书） |
| ECDSA P-256/384/521 | `ecdsa-sha2-nistp256` / `nistp384` / `nistp521` |

主体密钥与 CA 密钥可以交叉组合（例如 RSA 主体由 Ed25519 CA 签发）。
不支持把证书本身当作 CA（链式证书），也不支持已废弃的 `ssh-dss`。

## 安装

无需编译，直接把 `ssh_cert_validator` 包放入项目即可，运行环境需要
Python 3.10+ 与 `cryptography`。

## 快速上手

```python
from ssh_cert_validator import (
    CAVerifier,
    RevocationList,
    SSH_CERT_TYPE_USER,
    parse_certificate,
    validate_certificate,
)

cert_line = open("user_key-cert.pub").read()
cert = parse_certificate(cert_line)

# 1. 建立 CA 信任锚（可一次加入多个受信 CA）
verifier = CAVerifier.from_public_keys([open("user_ca.pub").read()])

# 2. 撤销列表（serial、serial 区间或 key ID）
revoked = RevocationList()
revoked.revoke_serial_range(100, 200)

# 3. 执行完整校验：验签 -> 类型 -> nonce -> 有效期 -> principal -> 撤销 -> 临界选项
result = validate_certificate(
    cert,
    verifier,
    expected_type=SSH_CERT_TYPE_USER,
    requested_principal="alice",       # 精确匹配，alice-admin 会被拒绝
    peer_address="10.0.0.7",            # 结合 source-address 校验
    revocation_list=revoked,
)

print(result.principal)          # alice
print(result.forced_command)     # 证书内 force-command，无则 None
```

只想做密码学验签、不跑策略时，可单独调用：

```python
verifier.verify(cert)            # 失败抛 VerificationError
verifier.is_valid(cert)          # 返回 bool
```

## 校验规则与边界

- **有效期**：遵循 OpenSSH 规则 `valid_after <= now < valid_before`，
  下界包含、上界排除；`valid_before = 2^64-1` 表示永久有效。`now` 可注入，
  便于测试边界。
- **nonce**：短于 32 字节直接拒绝（`WeakNonceError`）。
- **principal**：用户证书按目标用户名、主机证书按目标主机名做字节级精确比对；
  空列表表示该类型下对任意身份有效。
- **critical options**：无法识别的选项必须拒绝；`force-command`、
  `source-address` 只允许出现在用户证书上，主机证书携带即拒绝。
- **source-address**：对端地址必须命中选项中的某个 CIDR（含 IPv4/IPv6 与单地址）；
  存在该选项但拿不到对端地址时拒绝。
- **force-command**：校验通过后通过 `ValidationResult.forced_command` 返回，
  调用方需在会话中强制执行，忽略用户在命令行指定的命令。
- **撤销**：命中 serial、serial 区间或 key ID 即拒绝。

所有失败都通过具体异常类型表达，便于调用方分别处置：
`VerificationError`、`CertificateTypeError`、`WeakNonceError`、
`CertificateExpiredError`、`PrincipalMismatchError`、
`RevokedCertificateError`、`CriticalOptionError`、`SourceAddressError`。

## 模块结构

- `ssh_cert_validator/wire.py`：RFC 4251  wire 编解码原语。
- `ssh_cert_validator/certificate.py`：证书 blob 解析与数据类。
- `ssh_cert_validator/ca.py`：CA 信任存储与 Ed25519/RSA/ECDSA 验签。
- `ssh_cert_validator/policy.py`：principal、有效期、临界选项、撤销等策略。
- `ssh_cert_validator/builder.py`：内存证书构造器，用于测试与工具，产物可被
  官方 `ssh-keygen -L` 直接识别。

## 运行测试

```bash
python -m unittest
```

测试共 53 个用例，覆盖用户/主机证书、三种 CA 签名算法、错误 CA、principal
前缀混淆、撤销命中、短 nonce、有效期上下界、source-address 与 force-command
组合；当系统装有 `ssh-keygen` 时还会运行与官方工具的字节级互操作测试。
