# Flask MFA 服务

用 Python + Flask 重做的多因素认证模块，针对"换手机后 MFA 频繁失效、客服人工解绑"的问题，
把时间漂移、重放防护、一次性备用码、多设备、恢复换绑、渐进锁定、敏感操作二次验证和审计
全部内建，并提供一个只读管理页面。

## 安全特性与实现要点

| 需求 | 实现 |
| --- | --- |
| TOTP 时间漂移窗口 | 自实现 RFC 6238（`mfa_app/totp.py`），默认接受当前步 ±1 个 30 秒步长，常量时间比较 |
| 同一码不能用两次 | 每台设备记录 `last_counter`，只接受严格递增的 counter；窗口内的旧码也判重放并记审计 |
| 时钟往回拨 | 回拨只能产生 ≤ 已接受 counter 的码，被同一套单调 counter 逻辑拒绝（见 `test_clock_rollback.py`） |
| 备用码一次性、只存哈希 | 10 个高熵 base32 码，库存 HMAC-SHA256(pepper) 哈希；`used_at` + `WHERE used_at IS NULL` 原子消费，并发双花只能成功一次 |
| 多台设备 | 一个用户可绑定多台已确认设备，任一设备的 TOTP 均可登录，counter 按设备独立 |
| 换绑走恢复流程 | 消耗一个备用码 → 5 分钟恢复会话 → 绑定新设备，确认后旧设备全部注销 |
| 输错渐进锁定 | 第 5 次失败起锁定 15s，之后每次 +15s，封顶 300s；TOTP 与备用码失败共享计数；锁定期内一律拒绝 |
| 敏感操作二次验证 | 加/解设备、换绑、备用码再生、停用 MFA 需 step-up（默认 120s TTL） |
| 审计 | 所有登录、验证、拒绝、重放、锁定、恢复、管理员解锁均落 `audit_log`，含 IP、结果、详情 |
| 管理页面 | 管理员只读查看用户/设备/锁定状态与审计（按动作、用户名筛选 + 分页）；解锁走 CLI 并记审计 |
| 静态密钥保护 | TOTP 共享密钥用 Fernet（AES）加密后入库，不明文落盘 |

## 目录结构

```
mfa_app/
  clock.py          # 可注入时钟：冻结/快进/回拨，所有时间取数的唯一入口
  totp.py           # RFC 4226/6238 纯标准库实现 + otpauth URI
  crypto.py         # Fernet 加解密、备用码 HMAC 哈希
  config.py         # 全部阈值集中配置，环境变量可覆盖
  db.py             # SQLite 连接与 schema
  repositories.py   # 数据访问层
  services.py       # 业务规则：锁定、验证、注册、恢复、审计
  auth.py           # 登录/step-up/管理员装饰器
  routes_*.py       # auth / mfa / admin 三个蓝图
  templates/        # Jinja 模板（内联 CSS，无前端构建）
tests/              # 87 个 pytest，重点覆盖时间边界
run.py              # 开发入口
smoke_journey.py    # 端到端冒烟脚本（隔离模式运行）
```

## 快速开始

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt

# 建用户（首台设备在首次登录时通过引导流程绑定）
export FLASK_APP=run.py
.venv/bin/flask create-user alice '你的强密码'
.venv/bin/flask create-user boss '管理员密码' --admin

.venv/bin/flask --app run.py run
# 浏览器打开 http://127.0.0.1:5000/login
```

生产环境请先设置 `.env.example` 中的四个环境变量（尤其是 `MFA_TOTP_KEY` 与
`MFA_BACKUP_PEPPER`，未设置时仅生成进程内临时密钥，重启后密文无法解密）。

### 手动解锁（客服操作，会写审计）

```bash
.venv/bin/flask --app run.py unlock alice
```

## 测试

```bash
.venv/bin/python -m pytest                 # 全部 87 个
.venv/bin/python -I smoke_journey.py       # 端到端冒烟旅程
```

### 时间边界测试怎么覆盖的

时钟在每个测试开始时冻结在 1_000_000（位于某个 30 秒步内部，距切换点 20 秒），
随后用 `clock.advance()` 精确驱动：

- `test_totp.py`：RFC 6238 官方向量；切换点前 1ms / 切换点当刻 / 切换后 15s 三个位置；
  ±1 窗口接受、±2 步拒绝；与 pyotp 交叉验证。
- `test_clock_rollback.py`：同码重放、步进后旧码在窗口内仍被拒、时钟回拨 45s 拒绝、
  回拨后时钟追平又恢复、恰好卡在 30 秒切换点的接受与重放、多设备 counter 独立。
- `test_lockout.py`：第 5 次触发 15s 锁定、延迟 15/30/45…/300 递增封顶、
  锁定期计数不增长、到期自动清零、成功验证清零。
- `test_recovery.py` / `test_bootstrap.py`：恢复窗口 300s 过期、首台设备引导注册。

## 设计取舍与后续可加固项

- 备用码本身高熵（每组 5 字符 base32 × 2），故用 HMAC-SHA256 而非慢哈希；pepper 需妥善托管。
- 会话用 Flask 签名 cookie；多实例部署需共享 `MFA_SECRET_KEY`，或换服务端会话存储。
- 当前为单文件 SQLite + 同步请求；水平扩展时建议换 Postgres，备用码消费的 CAS 语句可直接沿用。
- TOTP 加密密钥的轮换（多 key 版本号）、认证器名称/图标、速率限制（IP 维度）可作为下一步。
