# CarbolicAcid (v0.3.1)

> 向英国外科医生约瑟夫·李斯特于1865年首次将 石炭酸 用于手术消毒致敬。
> CarbolicAcid 是一个 CoreDNS 插件，用于拦截向下游应答“投毒 IP”，且阻止“投毒 IP”进入 CoreDNS 缓存，如：

- 127.0.0.1
- 其他常见污染段

插件支持三种响应策略：

- drop：丢弃应答
- servfail：返回 SERVFAIL
- nxdomain：返回 NXDOMAIN

并提供可选的 IANA 预设保留地址作为黑名单。
黑名单构建顺序：

```
final = preset − exclude + include
```

CarbolicAcid插件是一个**汇编语言风格、无例外、无保护、无妥协**的 单纯 DNS 应答中 IP 地址记录的过滤器。
它不进行 DNSSEC 和 FQDN 过滤，也不进行大量解析结果是否指向同一个 IP 地址的过滤。
它不会替用户判断“哪些域名是安全的”，也不会阻止用户把系统玩坏。

请务必确保：

- 系统自身依赖的域名不会被CarbolicAcid误杀
- Windows 用户尤其需要注意
- 阅读本节内容并根据实际环境进行正确配置

如果把CarbolicAcid的安全性开到最大，却忘了放行局域网根域，那将会看到什么叫真正的“石炭酸式 DNS 消毒”：干净得连系统必需的 DNS 都活不下来。

所以请务必仔细阅读本说明。

---

## 0. ⚠ 系统兼容性警告

石炭酸（CarbolicAcid）是一个**纯响应过滤插件**，它不会对域名、FQDN、系统行为做任何例外处理。
插件只根据配置的 IP/CIDR 进行匹配，并按使用者的要求返回 `NXDOMAIN`、`SERVFAIL` 或 `DROP`。
**它不会试图保护用户的系统，也不会替用户做任何安全判断。**

这意味着：
> 如果用户把系统自身依赖的 DNS 查询“误杀”，系统可能会出现严重的功能异常。

如果配置错误：
> 可能会体验到当年 DOS 时代“写内存越界把系统玩死”的感觉。

**以下内容非常重要，请务必阅读。**

因为 DNS 协议的特性，必须允许 DNS 服务器能够正确回答自身 hostname 的 FQDN，例如：

```
# 请注意这不是配置示例，只是在解释CarbolicAcid工作原理，不要直接复制进实际使用的 Corefile 文件中。
"your-server-hostname" {
    # some plugins
}
```

这是所有操作系统的正常行为：
服务器在解析自身主机名的 FQDN 时，通常会因系统 hosts 或 resolver 内置逻辑得到 127.0.0.1，而不是来自上游 DNS。

同时，局域网内的终端在解析短主机名时，会自动补全服务器的域名，例如：

`terminal-hostname → terminal-hostname.<server-hostname>`

因此，终端发出的 DNS 查询会自然落入服务器域名的 zone 中，从而被正常放行。

⚠ 基于同样的原因，即使服务器自身操作系统把 DNS 指向其他上游服务器，局域网终端仍然会把 `terminal-hostname` 补全成 `terminal-hostname.<search-domain>` 并发送给 CoreDNS，因此仍然会被CarbolicAcid拦截。

而 DNS 投毒攻击返回的 127.0.0.1 通常来自完全不同的恶意域名，不会落入服务器域名的 zone，因此会被这种配置所拦截：

```
# 请注意这不是配置示例，只是在解释CarbolicAcid工作原理，不要直接复制进实际使用的 Corefile 文件中。
. {
    forward . 1.1.1.1
    carbolicacid {
        # 配置 preset iana 或 include 127.0.0.0/8
        preset iana
    }
}
```

这不是CarbolicAcid插件的错误，而是 DNS 协议的正常行为。

CarbolicAcid的主要安全效果来自 **“只放行服务器自身域名”** ，而次要安全效果，来自 **“拦截其余的 127.0.0.0/8 应答”** 。
  - “服务器自身域名” 指的是 DHCP 推送的 DNS 后缀（search-domain），不是 localhost，也不是 NetBIOS 名称。
  - CoreDNS 配置时，是把 "your-server-hostname" 释义为 FQDN ，作为一个权威域 (authoritative zone)

---

### 0.1 ⚠ Windows 系统（最需要注意）

Windows 在系统启动阶段会主动查询一系列域名，用于：

- WinHTTP
- RPC
- SMB
- LSA
- Winlogon
- 证书链验证
- 网络连通性检测（NCSI）
- 自动代理发现（WPAD）
- IPv6 反向解析

其中的 `hostname` 查询**必须成功**，否则 Windows 可能出现：

- UI 卡死
- 本地鼠标/键盘驱动无响应
- 远程桌面断开
- 服务无法启动
- 网络堆栈部分冻结
- DNS Client 阻塞
- 系统进入“半死锁”状态

然后在几分钟后恢复，在这个“半死机”状态中，系统所有功能都会接近停止。恢复后，会看到 CoreDNS 启动失败。

#### ⚠ 重要提示

如果配置使用 `preset iana` 或手动 include 了 `127.0.0.1/32`、`::1/128` 等地址，并且 Windows 的 DNS 指向了 CoreDNS，那么：

> Windows 会在 DNS 服务可达阶段向 CoreDNS 查询这些域名，
> 由CarbolicAcid拦截产生的解析结果，丢弃或返回 NXDOMAIN，系统可能直接卡死。

可以使用 `hostname` 或者 `echo %COMPUTERNAME%` 或者 `$env:COMPUTERNAME` 查询服务器的主机名称。

#### 建议（任选其一）：

- **在 Corefile 中为服务器自身域名创建独立 zone，并避免使用CarbolicAcid。**
- **在 Corefile 根域中 exclude `127.0.0.1/32` 和 `::1/128`，但不推荐这么做。**

---

### 0.2 Linux / BSD / Solaris 系列（风险较低）

这些系统通常不会在 DNS 服务开始响应阶段依赖 DNS 解析自身主机名，
但如果 `/etc/nsswitch.conf` 配置为：

```
hosts: dns files
```

则可能触发 DNS 查询。

#### 这些系统可能查询：

- `localhost` / `::1`
- 主机名（`hostname`）
- `.local`（mDNS）

#### UNIX‑like 系统主机名的存放位置

不同系统的 hostname 存放位置略有差异，但大体如下：

* **Linux（systemd 系列 - 如 debian 分支）**
  * `/etc/hostname`（静态主机名）
  * `/etc/hosts`（本地解析）
  * `hostnamectl`（管理器）
* **Linux（传统 SysV - 如 RedHat 分支）**
  * `/etc/sysconfig/network`（某些发行版）
  * `/etc/HOSTNAME`（旧式）
* **FreeBSD / OpenBSD / NetBSD**
  * `/etc/rc.conf` 中的 `hostname="foo.example.com"`
  * `/etc/hosts`（本地解析）
* **OpenIndiana / illumos / Solaris 系列**
  * `/etc/nodename`（系统主机名）
  * `/etc/hosts`（本地解析）

大多数可以使用 `hostname` 或 `cat /etc/hosts` 命令，获取到正确的主机名称。

这些文件决定系统在启动时如何设置主机名，以及是否需要 DNS 参与解析。

如果配置成了需要DNS服务参与解析，阻断这些域名的解析结果可能造成系统响应速度下降，但不至于假死。

#### 建议（任选其一）：

- **在 Corefile 中为服务器自身域名创建独立 zone，并避免使用CarbolicAcid。**
- **确保 `/etc/hosts` 中包含 `localhost` 和主机名**
- **在 Corefile 根域中 exclude `127.0.0.1/32` 和 `::1/128`，但不推荐这么做。**

---

### 0.3 总结以上

启用CarbolicAcid插件，必须在配置文件中放行服务器自身域名，也就是 Corefile 至少分成两个 zone ，只配置一个根域可能会造成至少是系统响应速度下降的副作用。

配置示例：

```
# 一定要把DNS服务器的主机名单独配置一个zone
# 把"your-server-hostname"连同引号在内，更换成实际使用的服务器 hostname 。
"your-server-hostname" {
    # 至少配置一个插件，否则 CoreDNS 会认为这个 zone 是“空的”，仍然会 fallback 到根 zone . {} ，例如启用一个开销最低的 log 。
    log
}

# 然后再配置其他权威域或者根域
. {
    forward . 1.1.1.1
    carbolicacid {
        [ preset iana | include 127.0.0.0/8 ]
    }
}
```

其中的 `"your-server-hostname"` 可以大写也可以小写，对操作系统来说，大小写产生的 ASCII / UTF-8 字符编码不一样，但对于DNS协议来说，是大小写不敏感的，但会保留大小写用于 DNS0x20 混淆（不影响匹配）。CoreDNS 也会把 Corefile 中配置成大写的 FQDN 转换成小写字母；而且大写字母会在查询请求报文中转换成小写字母，所以如果严格遵循 DNS 协议标准，应该填写小写的 hostname 。

但**不要直接复制**以上示例，粘贴进实际使用环境中，直接使用。使用者本地的 hostname 是什么，这个示例不知道。

而且至少在 `"your-server-hostname"`所在的 zone 中，启用一个插件，使其成为 authoritative zone ，或者说“激活”这个 zone，如果任何插件都没有填写，比如：

```
"your-server-hostname" {}
```

CoreDNS 会认为这个 zone 是“空的”，仍然会 fallback 到根 zone `. {}`，导致：

* 终端补全后的 FQDN 落入根 zone
* 被 CarbolicAcid 拦截
* 经历一次“石炭酸式 DNS 消毒”

`*` 因 macOS (NeXTSTEP) 现在不作为服务器系统使用，且其 resolver 行为与其他 UNIX-like 一致，无需特别说明。

---

## 1. Corefile 配置

**最简单配置（默认不做任何事）**

```
carbolicacid
```

等价于：

```
carbolicacid {
    preset none
    responses drop
}
```

---

## 2. 使用 IANA 预设黑名单

```
carbolicacid {
    preset iana
}
```

---

## 3. 添加自定义黑名单

```
carbolicacid {
    include 198.51.100.0/24
}
```

---

## 4. 排除某些段

```
carbolicacid {
    preset iana
    exclude 169.254.0.0/16
}
```

请注意，必须从某一范围排除特定IP地址段，不能从一片空白中排除些地址段。exclude 不能在一开始就设置一个特殊地址段，以保证不被过滤。

---

## 5. 设置毒应答处理策略（v0.3.1）

```
carbolicacid {
    responses drop
}
```

或：

```
carbolicacid {
    responses servfail
}
```

或：

```
carbolicacid {
    responses nxdomain
}
```

---

## 6. 默认行为

| 配置项       | 默认值  | 说明       |
| --------- | ---- | -------- |
| preset    | none | 不加载任何预设  |
| responses | drop | 丢弃毒应答    |
| include   | 空    | 不添加额外黑名单 |
| exclude   | 空    | 不排除任何段   |

---

## 7. 完整配置语法

```
carbolicacid {
    preset [none|iana]
    exclude CIDR
    include CIDR
    responses [drop|servfail|nxdomain]
}
```

---

## 8. 已知问题

- 不支持自动补全掩码，配置中 127.0.0.1 不等价于 127.0.0.1/32，目前在 Corefile 配置文件中，如果使用了 include/exclude 配置一个不带有掩码位数的地址，会产生错误。
- 阻断列表以固定模式生成，不能先以 include 生成一个大的网段，再从中间 exclude 排除一个小网段或者特定地址。
