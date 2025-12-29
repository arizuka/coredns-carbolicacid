# CarbolicAcid (v0.3.3)

> 向英国外科医生约瑟夫·李斯特于 1865 年首次将 **石炭酸** 用于手术消毒致敬。  
> CarbolicAcid 是一个 CoreDNS 插件，用于拦截发往下游的“投毒 IP”应答报文，并阻止“投毒 IP”进入 CoreDNS 缓存，例如：

- 127.0.0.1
- 10.0.0.0/8 或 192.168.0.0/16 本地网段
- ::1
- 100::/64 黑洞
- 其他常见污染段

插件支持以下毒应答处理策略（v0.3.3）：

- `drop`：丢弃应答，不返回给客户端
- `servfail`：返回 `SERVFAIL`
- `nxdomain`：返回 `NXDOMAIN`
- `bypass`：直接透传上游应答，并记录日志（仅审计，不拦截）

插件在单个实例中，使用“阻断表 + 允许表”的双表模型进行筛选：

- `preset iana` 根据 IANA 公布的特殊地址范围，其中“其中被标记为保留、特殊用途、或不用于公共互联网上路由的地址段”，来源页面：
  IPv4: `https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml`
  IPv6: `https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml`
  初始化一组“阻断前缀”，直接写入阻断表（blockList）。
- `preset allip` 会将 `0.0.0.0/0` 和 `::/0` 写入阻断表，表示“所有 IPv4 / IPv6 地址默认视为可阻断”，需配合 exclude 精确定义允许范围。
- `block` 会向阻断表追加前缀。
- 子配置项 `exclude` 只能用于修剪其“父配置项”所产生的前缀集合：
  - `preset iana { exclude X }` 中的 `X` 必须是 IANA 前缀集合的子网
  - `block 10.0.0.0/8 { exclude X }` 中的 `X` 必须是 10.0.0.0/8 的子网
  - `exclude` 不会跨节点检查整个阻断表，也不会作用于其他 `preset` 或 `block`。
  - 如果 exclude 不是其父节点前缀的子集，则在初始化阶段跳过其父配置项，查找下一条“preset”或“block”继续生成阻断表或允许表。

> 允许表优先于阻断表，只要命中允许表，就视为这一条应答可放行，跳过阻断表查询。
> 未命中允许表则匹配阻断表，如果命中阻断表，则会拦截发给下游的应答报文，并可以阻止被拦截应答写入 CoreDNS 缓存（需要 CarbolicAcid 在插件链中位于 Cache 之前）。
> 如果 CarbolicAcid 的当前实例配置中，未出现 `exclude` ，则 allowList 为空，匹配流程会直接进入阻断表检查，也就是当前实例跳过允许表匹配，只进行阻断表匹配流程。

CarbolicAcid 插件是一个 **汇编语言风格、非智能化、可用于ISP网络** 的
**“仅针对 DNS 应答中 IP 地址（A / AAAA）的过滤器”**。

- 它 **不** 做 DNSSEC 校验，也 **不** 做 FQDN / 域名过滤  
- 它 **不** 尝试判断“哪些域名是安全的”  
- 它 **不** 会帮用户避免把系统玩坏  
- 它 **不会对单条记录做“部分放行”**：  
  一旦某条 A/AAAA 命中拦截列表，视为整个应答报文已被投毒，按策略处理整个响应

请务必确保：

- 系统自身依赖的域名不会被 CarbolicAcid 误杀
- Windows 用户尤其需要注意
- 完整阅读本说明，并结合实际环境进行正确配置

如果把 CarbolicAcid 的安全性开到最大，却忘了放行局域网根域，那将会看到什么叫真正的“石炭酸式 DNS 消毒”：
干净得连系统必需的 DNS 都活不下来。

所以请务必仔细阅读本说明。

---

## 1. ⚠ 系统兼容性警告

CarbolicAcid 是一个 **纯“响应过滤”插件**：

- 只看 DNS 应答中的 `A` / `AAAA` 记录
- 只根据配置的 IP / CIDR 进行匹配
- 按使用者配置返回 `NXDOMAIN` / `SERVFAIL` / `DROP` / `BYPASS`
- **不针对域名 / FQDN / 客户端 /协议栈做任何特殊照顾或例外处理**

它不会：

- 识别用户配置是不是“对系统有危险”
- 在配置错误时替用户保护系统
- 帮用户做任何“善意修正”或“安全兜底”

这意味着：

> 如果用户把系统自身依赖的 DNS 查询“误杀”，系统可能会出现严重功能异常。

如果配置错误：

> 可能会体验到当年 DOS 时代“写内存越界把系统玩死”的感觉。

**以下内容非常重要，请务必阅读。**

---

### 1.1 关于“服务器自身域名”与 127.0.0.1 / ::1

操作系统和局域网终端在启动或解析短主机名时，会查询服务器自身的完整主机名（FQDN）。  
这些查询必须被正常放行，否则可能导致系统启动缓慢、网络异常或 Windows 假死。

请将服务器的 FQDN，单独配置为一个 zone，

- 在有域环境中，它通常是 `<hostname>.<domain>`

- 在无域环境中，它通常是 `<hostname>.`
  例如：
  
  ```
  "server.example.com" {
    log
  }
  ```

这样可以确保对服务器自身主机名的查询不会落入根域，从而避免被 CarbolicAcid 拦截。

需要注意：

- 服务器的 FQDN 不一定是 `localhost`，也不一定是 Windows 的 NetBIOS 名称
- 它与 search-domain（DNS 后缀）不是同一个概念

服务器的 FQDN 不一定包含 `search-domain`：

- 当服务器加入了 AD 域，或者使用了 DHCP option 15 或 119 时，FQDN 会在 `<hostname>` 后添加 `<search-domain>` 来组成 FQDN，
- 但在没有 AD 域或者没有 DHCP option 15 或 119 时，仅以 `<hostname>.` 作为自身 FQDN，这也就是前面为什么说“不一定是”。

后面在 Windows 小节会详细说明如何获取准确的 Windows 系统 FQDN。

CarbolicAcid 的安全效果依赖于将服务器自身域名与根域分离：

1. 放行服务器自身域名所在的 zone
2. 在根域中拦截落入拦截列表的 127.0.0.0/8、::1 等投毒应答

---

### 1.2 ⚠ Windows 系统（最需要注意）

Windows 在系统启动和登录阶段会主动查询一系列域名，用于：

- WinHTTP
- RPC
- SMB
- LSA
- Winlogon
- 证书链验证
- 网络连通性检测（NCSI）
- 自动代理发现（WPAD）
- IPv6 反向解析等

其中的 `hostname` 查询在某些阶段 **必须成功**，否则可能出现：

- UI 卡死
- 本地鼠标 / 键盘驱动无响应
- 远程桌面断开
- 服务无法启动
- 网络堆栈部分冻结
- DNS Client 阻塞
- 系统进入“半死锁”状态，几分钟后才逐渐恢复

恢复后，能在日志里看到 CoreDNS / CarbolicAcid 启动失败或响应异常。

#### ⚠ 重要提示

如果：

- 在 Corefile 中启用了 `preset iana` 或手动 `block 127.0.0.1/32`、`::1/128`
- 并且 Windows 的 DNS 指向了这台 CoreDNS + CarbolicAcid

那么：

> Windows 会在 DNS 服务可达阶段向 CoreDNS 查询一堆“系统级域名”，
> 如果这些查询被 CarbolicAcid 拦截，丢弃或返回 NXDOMAIN / SERVFAIL，
> 系统可能直接卡死一段时间，或者表现出严重的不稳定。

可以使用：

未加入 AD 域的 Windows，避免 `<WORKGROUP>` 产生干扰：

- `$env:COMPUTERNAME` 
  在 PowerShell 5 或 7 中，读取未加入 AD 域的 Windows 系统的 hostname 作为服务器 FQDN。

加入 AD 域的 Windows：

- `$env:COMPUTERNAME + "." + (Get-CimInstance Win32_ComputerSystem).Domain`
  在 PowerShell 5 或 7 中，读取加入了 AD 域的 Windows 系统的 hostname 作为服务器 FQDN。

注意，在未加入 AD 域的 Windows 上执行 `$env:COMPUTERNAME + "." + (Get-CimInstance Win32_ComputerSystem).Domain`
会生成 `<HOSTNAME>.<WORKGROUP>` 这种回显，而 `<WORKGROUP>` 并不会参与生成 Windows 系统的 FQDN，这也就是 Windows 系统最需要注意的地方。

#### 建议（任选其一）：

- **在 Corefile 中为服务器自身域名创建独立 zone，并在该 zone 中不要使用 CarbolicAcid 拦截内容为 127.0.0.1 的响应。**
- 将服务器的 Windows 系统的上游 DNS 配置成自身以外的其他 DNS 服务器，也就是不配置成 127.0.0.1 或服务器网卡地址，此方法是在降低 CarbolicAcid 的防护水平，不建议使用这个方法。
- 仅在**充分理解风险**的前提下，在根域中使用 exclude 排除对 `127.0.0.1/32` 和 `::1/128` 应答内容的筛选，此方法是在降低 CarbolicAcid 的防护水平，不建议使用这个方法。

---

### 1.3 Linux / BSD / Solaris 系列（风险较低）

这些系统通常不会在 DNS 服务刚可用的阶段依赖 “远程 DNS” 解析自身主机名，但如果 `/etc/nsswitch.conf` 配置为：

```text
hosts: dns files
```

则可能在启动过程中由 resolver 发起主机名解析。

可能涉及的查询包括：

- `localhost` / `::1`
- 主机名（`hostname`）
- `.local`（mDNS）

通常可以通过 `hostname -f` 获取有效的服务器 FQDN。

如果这些系统被配置成依赖 DNS 解析自身主机名，而在 CarbolicAcid 中把相关结果拦截掉：

- 可能会造成系统启动变慢、部分服务延迟
- 一般不至于像 Windows 那样假死，但仍然是不推荐的配置方式

#### 解决办法（任选其一）：

- **在 Corefile 中为服务器自身域名创建独立 zone，放行 127.0.0.1。**
- **确保 `/etc/hosts` 中包含 `localhost` 和主机名指向 127.0.0.1 / ::1**
- 将服务器的系统的上游 DNS 配置成自身以外的其他 DNS 服务器，也就是不配置成 127.0.0.1 或服务器网卡地址，此方法是在降低 CarbolicAcid 的防护水平，不建议使用这个方法。
- 仅在**充分理解风险**的前提下，在根域中使用 exclude 排除对 `127.0.0.1/32` 和 `::1/128` 应答内容的筛选，此方法是在降低 CarbolicAcid 的防护水平，不建议使用这个方法。

---

### 1.4 局域网内的终端设备

局域网内的终端设备，根据其自身操作系统，也还是会生成自身的 FQDN，
把 `<terminal-hostname>` 补全成 `<terminal-hostname>.<search-domain>`
并以此发送给其自身的上游服务器，这些查询通常不会返回 127.0.0.1，而是返回 NXDOMAIN 或 SERVFAIL，
因此不会被 CarbolicAcid 误杀。

### 1.5 总结以上

启用 CarbolicAcid 插件时，应当：

- 在配置文件中明确放行“ DNS 服务器自身域名所对应的 FQDN ”
- 让 Corefile 至少分成两个 zone  
  （一个专门服务于服务器自身 / 局域网内部；一个作为根域对外转发 + CarbolicAcid）

只配置一个根域 `. {}` 并在里面启用 CarbolicAcid，并且让它去拦截 127.0.0.1 的投毒地址时，
**几乎可以保证用户会看到至少是“系统响应明显下降”的副作用，更糟糕时直接进入“石炭酸式 DNS 消毒”。**

一个最小可理解的结构示意：

```corefile
# 建议把 DNS 服务器的主机名单独配置一个 zone
# 把 "your-server-fqdn"（连同引号）替换成实际服务器 FQDN
"your-server-fqdn" {
    # 至少启用一个插件，使其成为“激活”的 authoritative zone
    # 否则 CoreDNS 认为这是个空 zone，仍然会 fallback 到根 zone
    carbolicacid {
        preset allip {
            exclude 127.0.0.1
            exclude ::1
        }
        responses bypass
    }
}

# 然后再配置根域或其他权威域
. {
    forward . 1.1.1.1
    carbolicacid {
        preset iana
        # 或者 block 127.0.0.0/8 等，preset 以及 block 后可以不加括号，视为没有 exclude

        # 如果希望加快 DNS 查询过程，避免等待 drop 时产生的几秒延迟
        responses nxdomain
    }
}
```

关于大小写：

- 对 DNS 协议来说，域名大小写不敏感，但会保留大小写用于 DNS0x20 混淆  
- CoreDNS 会把 Corefile 中的 FQDN 规范化为小写  
- 查询报文中的 FQDN 也会被以小写方式参与匹配  
- **建议在配置中使用小写 "your-server-fqdn"**，以符合 DNS 规范和多数实现习惯

⚠ 再次强调：

```corefile
"your-server-fqdn" {}
```

这样的 zone 是“空”的，CoreDNS 会 fallback 到根 zone，  
等效于没为自身主机名单独划出一个安全区，  
终端补全后的 FQDN 仍然落入根 zone，被 CarbolicAcid 拦截，  
从而经历一次完整的“石炭酸式 DNS 消毒”。

---

## 2. Corefile 配置概览

**最简单配置（默认不做任何事）**

```corefile
carbolicacid
```

等价于：

```corefile
carbolicacid {
    preset none
    responses drop
}
```

含义：

- 不加载任何预设拦截列表（`preset none`）
- 毒应答处理策略为 `drop`
- 因为没有 `block`，此时实际上不会拦截任何 IP

---

## 3. 预设拦截列表（preset）

### 3.1 使用 IANA 预设（保留地址等）

```corefile
carbolicacid {
    preset iana
}
```

`preset iana` 会将 IANA 保留的典型地址段（如内网 / 保留 / 回环等）加入拦截列表构建基础集合。  
可以在此基础上继续通过 `block` / `exclude` 做微调：

```corefile
carbolicacid {
    preset iana { exclude 169.254.0.0/16 }
    block  192.88.99.0/24
}
```

构建过程可以理解为：

- `preset iana` 和后续的 `block` 一起构成候选阻断集合（blockList）
- `exclude` 会从这些候选集合中切出一部分前缀，放入允许表（allowList）
- 之后匹配时，先查 allowList，再查 blockList

---

### 3.2 使用 allip 预设（匹配所有 IP）

```corefile
carbolicacid {
    preset allip
}
```

`preset allip` 展开为：

- `0.0.0.0/0`
- `::/0`

即：匹配所有 IPv4 + IPv6 地址。  
在这种模式下，如果不做 `exclude`，**所有 A / AAAA 应答都将命中阻断表，除非被 allowList 放行**。

典型用途：

- 配合 `responses bypass` 做审计  
- 配合 `exclude` 放行极少数网段，拦截其余所有地址

示例：

```corefile
carbolicacid {
    preset allip {
        exclude 10.0.0.0/8
        exclude 192.168.0.0/16
    }
    responses drop
}
```

含义：

- 除 10.0.0.0/8 和 192.168.0.0/16 外，所有 A / AAAA 都视为“毒应答”并丢弃
- 适合使用在内网域名的防投毒策略上，或做严格的“默认拒绝”策略（慎用）

---

### 3.3 preset none（显式关闭预设）

```corefile
carbolicacid {
    preset none
}
```

- 不加载任何预设拦截列表
- 此时必须配合 `block` 才会实际拦截任何 IP
- 如果对预设不放心，这里可以进行显式配置

`preset none` 不允许挂 `exclude`（没有父集合可排除），  
如果为 `preset none` 配置了 `exclude`，CarbolicAcid `init` 将失败。

---

## 4. 添加自定义拦截列表（block）

```corefile
carbolicacid {
    block 198.51.100.0/24
}
```

注意（v0.3.3 中）：

- `block` / `exclude` 都必须是合法 CIDR：
  - 支持显式写法：`1.2.3.4/32`、`2001:db8::1/128`
  - 也支持省略掩码：`1.2.3.4` 会自动视为 `1.2.3.4/32`，`2001:db8::1` 会视为 `2001:db8::1/128`
- 所有 CIDR 最终都经由 `net.ParseCIDR` 做合法性检查，非法地址将导致插件初始化失败

`block` 可以与 `preset` 混用：

```corefile
carbolicacid {
    preset iana
    block 224.0.0.0/4
}
```

---

## 5. 排除某些段（exclude）与“子集检查”

```corefile
carbolicacid {
    preset iana { exclude 169.254.0.0/16 }
}
```

v0.3.3 中对 `exclude` 继续执行 v0.3.2 引入的 **“子集约束”**：

> 所有 `exclude` 必须是真正“属于其父配置项（对应的 preset 或 block）所产生前缀集合”的子集，  
> 否则视为配置错误，整个插件初始化失败。

也就是说：

- 可以从 `preset` 或 `block` 产生的集合中排除一小段：
  - 如：`preset iana` 包含 10.0.0.0/8  
  - 可以 `exclude 10.0.1.0/24`
- **不能** 从一个“空集合”里排除：
  - 如：只写 `exclude 1.2.3.0/24` 而不配置任何 `preset` / `block` → 报错
- **不能** 排除一个“与任何父集合都不相交”的段：
  - 如：`preset iana` 后写 `exclude 8.8.8.0/24` → 报错（不属于任何父集合）

这是一个“硬安全规则”：

- 目的是防止“用户以为自己排除成功，实际上根本没生效”的错觉
- 一旦 `exclude` 配错，不是“静默忽略”，而是 **整个配置直接失败**

---

## 6. 毒应答处理策略（responses / action）

```corefile
carbolicacid {
    responses drop
}
```

或：

```corefile
carbolicacid {
    responses servfail
}
```

或：

```corefile
carbolicacid {
    responses nxdomain
}
```

或（v0.3.3 新增）：

```corefile
carbolicacid {
    responses bypass
}
```

语义：

- `drop`：丢弃应答，不返回给客户端，也不缓存
- `servfail`：返回 `SERVFAIL`，提示“上游有问题”
- `nxdomain`：返回 `NXDOMAIN`，提示“域名不存在”
- `bypass`：**不拦截**，直接把上游应答透传给客户端，但记录日志  
  - 用于 **审计 / 观测** 环境，而不是实际防护  
  - 可以配合 `preset allip` 做“全量观测”模式

---

## 7. 默认行为

| 配置项       | 默认值  | 说明                 |
| --------- | ---- | ------------------ |
| preset    | none | 不加载任何预设            |
| responses | drop | 对命中拦截列表的应答执行 `drop` |
| block     | 空    | 不添加任何额外拦截列表         |
| exclude   | 空    | 不排除任何段             |

在默认 `preset none` 且没有 `block` 的情况下：

- 实际上 **不会拦截任何 IP**
- 只是在 CoreDNS 中“挂了一个什么都不做的 CarbolicAcid”

---

## 8. 完整配置语法（v0.3.3）

```corefile
carbolicacid {
    preset [none|iana|allip] { exclude CIDR }
    block  CIDR { exclude CIDR }
    responses [drop|servfail|nxdomain|bypass]
}
```

约束与行为（v0.3.3）：

- 所有 CIDR 必须合法；可以显式带掩码，也可以省略掩码（单 IP 将补全为 /32 或 /128）
- `preset none` 不允许挂 `exclude`
- 任意 `exclude` 必须是某个父集合（`preset` 或 `block`）的子网，否则 init 失败
- 在一个应答报文中：
  - 只要有任意一条 `A` / `AAAA` 命中拦截列表，即视为“整报文被投毒”
  - 整个应答按 `responses` 策略处理
  - **不会** 做“部分记录放行”
- `allowList`（由 `exclude` 形成）相对于 `blockList` 具有优先级：
  - 同一应答中，若存在某条记录命中 `allowList`，视为整报文允许放行

---

## 9. 已知行为与非特性说明（v0.3.3）

- **支持对单 IP 地址自动补全掩码（v0.3.3）**
  - `127.0.0.1` 等价于 `127.0.0.1/32`
  - `::1` 等价于 `::1/128`
  - 对明显不合法的写法仍然会在初始化阶段报错
- **不做 RR 级别的“部分过滤”**  
  - 一旦某条 `A` / `AAAA` 命中拦截列表  
  - 视为整个响应报文被投毒  
  - 不会“删掉某一条记录再转发剩余内容”，这是刻意设计，不与 DNS 报文结构玩擦边球
- **不处理非 A / AAAA 的记录类型**  
  - `CNAME` / `TXT` / `MX` / `SRV` 等一律不参与匹配  
  - 插件只关注 IP 地址级的 A / AAAA
- **exclude 行为严格受子集约束**  
  - 不能“从一片空白中排除”地址段  
  - 不能排除一个完全不属于父集合的网段  
  - 配错即父集合配置失败，不做静默容错

---

v0.3.3 的目标，是把 CarbolicAcid 打磨成一个：

- 行为**极度显式**
- 安全逻辑**对用户完全诚实**
- 对配置错误**零容忍**（宁可启动失败也不做 silent fix）
- 对 ISP / 高并发场景**足够轻量且可预期**

如果在阅读后仍有不确定之处，请先在测试环境中模拟一遍自己的 Corefile，再部署到生产环境。
