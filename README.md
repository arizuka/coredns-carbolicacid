# **CarbolicAcid (v0.3.4)**  
CarbolicAcid is a CoreDNS plugin for filtering poisoned DNS responses.
To enable CarbolicAcid as a CoreDNS plugin, please refer to the official CoreDNS documentation:
https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/

> Named in tribute to Joseph Lister, the British surgeon who first used **carbolic acid** for surgical antisepsis in 1865.  
> CarbolicAcid intercepts DNS responses containing **poisoned IP addresses** and prevents them from reaching downstream clients or entering the CoreDNS cache.  
> Examples include:

- `127.0.0.1`
- Private networks such as `10.0.0.0/8` or `192.168.0.0/16`
- `::1`
- `100::/64` (blackhole)
- Other commonly abused ranges

Supported response actions:

- `drop` — silently discard the response  
- `servfail` — return `SERVFAIL`  
- `nxdomain` — return `NXDOMAIN`  
- `bypass` — pass upstream response through unchanged and log it (audit‑only)

Each plugin instance uses a **dual‑table model** consisting of a blockList and an allowList:

- `preset iana` loads IANA‑defined special‑use and reserved prefixes  
  (IPv4: https://www.iana.org/assignments/iana-ipv4-special-registry/  
   IPv6: https://www.iana.org/assignments/iana-ipv6-special-registry/)  
  These prefixes are inserted directly into the blockList.

- `preset allip` inserts `0.0.0.0/0` and `::/0` into the blockList, treating **all IPv4/IPv6 addresses as blockable by default**.  
  Exclusions must be used to define the allowed ranges.

- `block` appends additional prefixes to the blockList.

- `exclude` may only carve out sub‑prefixes from its **parent rule**:  
  - In `preset iana { exclude X }`, `X` must be a subnet of the IANA prefix set  
  - In `block 10.0.0.0/8 { exclude X }`, `X` must be a subnet of `10.0.0.0/8`  
  - `exclude` does **not** operate across nodes and does **not** affect other presets or blocks  
  - If an exclude is not a valid subnet of its parent, the parent rule is skipped during initialization and the next preset/block is processed

Matching behavior:

- **allowList has priority** — if any A/AAAA record matches allowList, the entire response is allowed and blockList is skipped  
- If allowList does not match, blockList is evaluated; any match triggers the configured response action  
- When CarbolicAcid is placed before the Cache plugin, intercepted responses will not enter the CoreDNS cache

CarbolicAcid is intentionally designed as an **old‑school, assembly‑style, non‑smart, ISP‑grade filter** that operates **only on IP addresses (A/AAAA)**:

- It does **not** validate DNSSEC  
- It does **not** filter by domain or FQDN  
- It does **not** attempt to guess which domains are “safe”  
- It does **not** protect users from misconfiguration  
- It does **not** partially filter responses —  
  **one poisoned A/AAAA record poisons the entire response**

Please ensure:

- System‑critical DNS names are not accidentally blocked  
- Windows users should be especially cautious  
- Read this document carefully and configure according to your environment

If you enable maximum strictness without proper exclusions, you may experience true  
**“carbolic‑acid‑style DNS sterilization”** — so clean that even your system’s own DNS won’t survive.

---

# **1. ⚠ System Compatibility Warning**

CarbolicAcid is a **pure response filter**:

- It only inspects `A` / `AAAA` records  
- It only matches IPs and CIDRs  
- It only returns what *you* configure: `NXDOMAIN` / `SERVFAIL` / `DROP` / `BYPASS`  
- It provides **no special handling** for domains, FQDNs, clients, or protocol stacks

It will **not**:

- Detect whether your configuration is dangerous  
- Protect the system from your mistakes  
- Apply “helpful corrections” or “safety fallbacks”

Meaning:

> If you accidentally block DNS names your system depends on, the system may behave very badly.

If misconfigured:

> You may relive the DOS era where “writing past array bounds kills the whole machine.”

**The following content is extremely important. Please read carefully.**

---

## **1.1 Server FQDN and 127.0.0.1 / ::1**

During boot and short‑hostname resolution, both the OS and LAN clients will query the server’s **own FQDN**.  
These queries **must** be allowed, or you may experience:

- Slow boot  
- Network instability  
- Windows UI freeze or partial deadlock

You must configure the server’s FQDN as a dedicated CoreDNS zone.

- In domain environments: `<hostname>.<domain>`  
- In non‑domain environments: `<hostname>.`

Example:

```corefile
"server.example.com" {
    log
}
```

This ensures hostname‑related queries do **not** fall into the root zone, where CarbolicAcid may block them.

Important notes:

- The server’s FQDN is **not** `localhost`  
- It is **not** the Windows NetBIOS name  
- It is **not** the search‑domain  
- FQDN may or may not include the search‑domain depending on:
  - AD membership  
  - DHCP option 15 / 119  
  - Local resolver configuration

A later section explains how to correctly obtain the Windows FQDN.

CarbolicAcid’s safety depends on separating:

1. The server’s own FQDN zone (must be allowed)  
2. The root zone (where poisoned responses are intercepted)

---

## **1.2 ⚠ Windows Systems (Highest Risk)**

Windows performs numerous DNS lookups during boot and login:

- WinHTTP  
- RPC  
- SMB  
- LSA  
- Winlogon  
- Certificate chain validation  
- NCSI  
- WPAD  
- IPv6 reverse lookups  
- And more

Some hostname lookups **must succeed**, or Windows may:

- Freeze temporarily  
- Stop responding to mouse/keyboard input  
- Drop RDP sessions  
- Fail to start services  
- Partially deadlock the network stack  
- Block the DNS Client  
- Enter a “half‑deadlock” state for several minutes

After recovery, you may find CoreDNS / CarbolicAcid errors in the logs.

### ⚠ Critical Warning

If:

- You enable `preset iana` or manually block `127.0.0.1/32` or `::1/128`, **and**
- Windows points its DNS to this CoreDNS + CarbolicAcid instance

Then:

> Windows will query system‑critical names.  
> If CarbolicAcid blocks them, Windows may freeze or behave unpredictably.

But don't worry — with enough patience, Windows may eventually unfreeze itself.  
Until then, even the logging subsystem will remain completely silent.  
I've experienced this myself.

### Obtaining the Windows FQDN

Standalone Windows (WORKGROUP):

```powershell
$env:COMPUTERNAME
```

Domain‑joined Windows:

```powershell
$env:COMPUTERNAME + "." + (Get-CimInstance Win32_ComputerSystem).Domain
```

⚠ Note:  
On standalone Windows, the above may output `<HOSTNAME>.WORKGROUP`,  
but **WORKGROUP is not a DNS domain** and must not be used as the FQDN.

### Recommended (choose one):

- **Create a dedicated zone for the server’s FQDN and do NOT block 127.0.0.1 / ::1 in that zone**  
- Point Windows to another DNS server (reduces protection; not recommended)  
- Use `exclude 127.0.0.1/32` and `exclude ::1/128` in the root zone  
  (reduces protection; not recommended)

---

## **1.3 Linux / BSD / Solaris (Lower Risk)**

These systems usually resolve their own hostname via `/etc/hosts`.  
However, if `/etc/nsswitch.conf` contains:

```
hosts: dns files
```

then DNS may be used during boot.

Typical queries include:

- `localhost` / `::1`  
- The system hostname  
- `.local` (mDNS)

Use:

```
hostname -f
```

to obtain the FQDN.

If CarbolicAcid blocks these lookups:

- Boot may slow down  
- Some services may delay  
- But usually not as severe as Windows

### Recommended:

- **Create a dedicated zone for the server’s FQDN and allow 127.0.0.1**  
- **Ensure `/etc/hosts` contains hostname → 127.0.0.1 / ::1**  
- Or (not recommended) exclude 127.0.0.1 / ::1 in the root zone

---

## **1.4 LAN Clients**

LAN clients generate their own FQDNs by appending the search‑domain:

```
pc01 → pc01.<search-domain>
```

These queries normally **do not** resolve to 127.0.0.1 and therefore are **not** blocked by CarbolicAcid.

---

## **1.5 Summary**

When using CarbolicAcid:

- Always allow the server’s own FQDN  
- Always split CoreDNS into at least two zones:
  - One for the server’s FQDN (safe zone)  
  - One for the root zone (with CarbolicAcid enabled)

Using only a root zone with CarbolicAcid enabled and blocking 127.0.0.1 is almost guaranteed to cause system instability — a true **“carbolic‑acid DNS sterilization.”**

Example minimal configuration:

```corefile
"your-server-fqdn" {
    carbolicacid {
        preset allip {
            exclude 127.0.0.1
            exclude ::1
        }
        responses bypass
    }
}

. {
    forward . 1.1.1.1
    carbolicacid {
        preset iana
        responses nxdomain
    }
}
```

DNS is case‑insensitive but case‑preserving.  
CoreDNS normalizes Corefile FQDNs to lowercase.  
**Use lowercase for zone names.**

⚠ Reminder:

```corefile
"your-server-fqdn" {}
```

is an **empty zone**, and CoreDNS will fall back to the root zone —  
meaning your server’s own hostname queries will still be filtered by CarbolicAcid,  
leading to a full **carbolic‑acid‑style DNS sterilization**.

---

# **2. Corefile Overview**

### Minimal configuration (does nothing):

```corefile
carbolicacid
```

Equivalent to:

```corefile
carbolicacid {
    preset none
    responses drop
}
```

Meaning:

- No preset blockList (`preset none`)  
- Default action is `drop`  
- With no `block`, **no IPs are actually blocked**

---

# **3. Presets**

## **3.1 preset iana (IANA special-use/reserved prefixes)**

```corefile
carbolicacid {
    preset iana
}
```

`preset iana` loads the IANA‑defined special‑use/reserved prefixes  
(e.g., private networks, loopback, link‑local, documentation ranges).

You may refine them:

```corefile
carbolicacid {
    preset iana { exclude 169.254.0.0/16 }
    block 192.88.99.0/24
}
```

Conceptually:

- `preset iana` + `block` together form the candidate blockList  
- `exclude` extracts sub‑prefixes into the allowList  
- Matching order: **allowList → blockList**

---

## **3.2 preset allip (match all IPs)**

```corefile
carbolicacid {
    preset allip
}
```

Expands to:

- `0.0.0.0/0`
- `::/0`

Meaning: **all IPv4 + IPv6 addresses are blockable**.  
Without `exclude`, **every A/AAAA response will be blocked** unless allowed.

Typical use cases:

- Audit mode with `responses bypass`  
- “Default deny” policies with carefully defined exclusions

Example:

```corefile
carbolicacid {
    preset allip {
        exclude 10.0.0.0/8
        exclude 192.168.0.0/16
    }
    responses drop
}
```

Meaning:

- Everything except 10.0.0.0/8 and 192.168.0.0/16 is treated as poisoned  
- Useful for strict internal DNS filtering (use with caution)

---

## **3.3 preset none (explicitly disable presets)**

```corefile
carbolicacid {
    preset none
}
```

- Loads no preset blockList  
- You must use `block` to block anything  
- Useful if you want full manual control

`preset none` **cannot** have `exclude` (no parent set).  
If you attach an `exclude`, initialization fails.

---

# **4. Custom Block Entries**

```corefile
carbolicacid {
    block 198.51.100.0/24
}
```

Notes:

- `block` and `exclude` must be valid CIDRs:
  - Explicit: `1.2.3.4/32`, `2001:db8::1/128`
  - Implicit: `1.2.3.4` → `/32`, `2001:db8::1` → `/128`
- All prefixes are validated via `net.ParseCIDR`; invalid entries cause initialization failure

`block` may be combined with presets:

```corefile
carbolicacid {
    preset iana
    block 224.0.0.0/4
}
```

---

# **5. exclude and Subset Enforcement**

```corefile
carbolicacid {
    preset iana { exclude 169.254.0.0/16 }
}
```

**Subset rule:**

> Every `exclude` must be a strict subnet of its parent rule (preset or block).  
> Otherwise, initialization fails.

Meaning:

- You may carve out a smaller prefix from a preset/block:
  - If `preset iana` includes 10.0.0.0/8  
  - You may `exclude 10.0.1.0/24`
- You **cannot** exclude from an empty set:
  - `exclude 1.2.3.0/24` without any preset/block → error
- You **cannot** exclude unrelated prefixes:
  - `preset iana` + `exclude 8.8.8.0/24` → error

This is a **hard safety rule**:

- Prevents “I thought I excluded it, but nothing happened” confusion  
- Misconfiguration is **not silently ignored** — initialization fails

---

# **6. Response Actions**

```corefile
carbolicacid {
    responses drop
}
```

or:

```corefile
responses servfail
responses nxdomain
responses bypass
```

Meaning:

- `drop` — discard response, do not return or cache  
- `servfail` — return `SERVFAIL`  
- `nxdomain` — return `NXDOMAIN`  
- `bypass` — pass upstream response unchanged and log it  
  - Useful for **audit/observation**, not protection  
  - Often paired with `preset allip` for full‑visibility mode

---

# **7. Plugin Behavior**

## **7.1 Default Options**

| Option    | Default | Meaning |
|----------|---------|---------|
| preset    | none | No preset blockList |
| responses | drop | Drop poisoned responses |
| block     | empty | No custom blocks |
| exclude   | empty | No exclusions |

With `preset none` and no `block`:

- **No IPs are blocked**
- CarbolicAcid effectively “does nothing”

---

## **7.2 Matching Flow & Short‑Circuit Rules**

CarbolicAcid uses a **dual‑table model** with allowList priority:

1. **allowList first**  
   If any A/AAAA record matches allowList, the entire response is allowed  
   and blockList is skipped.

2. **Otherwise, evaluate blockList**  
   If any record matches blockList, the configured action is applied.

3. **If placed before the Cache plugin**,  
   blocked responses will not enter the CoreDNS cache.

4. If no `exclude` is configured, allowList is empty,  
   and matching skips allowList entirely.

5. If `preset allip` is used, the instance enters **full‑block mode**:
   - blockList is skipped entirely  
   - If exclusions exist, they form the allowList  
   - If no exclusions exist, allowList is empty and **all responses are blocked**  
   In other words: `preset allip` performs **allowList‑only matching**.

---

# **8. Full Syntax (v0.3.4)**

```corefile
carbolicacid {
    preset [none|iana|allip] { exclude CIDR }
    block  CIDR { exclude CIDR }
    responses [drop|servfail|nxdomain|bypass]
}
```

Rules:

- CIDRs may be explicit or implicit (`/32` or `/128`)  
- `preset none` cannot have `exclude`  
- Every `exclude` must be a subnet of its parent  
- In a DNS response:
  - Any poisoned A/AAAA record poisons the entire response  
  - The entire response is processed according to `responses`  
  - **No partial filtering**  
- allowList overrides blockList

---

# **9. Known Behaviors & Non‑Features**

- **Automatic mask completion**  
  - `127.0.0.1` → `/32`  
  - `::1` → `/128`  
  - Invalid CIDRs cause initialization failure

- **No partial RR filtering**  
  - One poisoned A/AAAA record → entire response poisoned  
  - No “remove one record and forward the rest” behavior

- **Non‑A/AAAA records are ignored**  
  - `CNAME`, `TXT`, `MX`, `SRV`, etc. are not inspected

- **Strict subset enforcement for exclude**  
  - Cannot exclude from empty sets  
  - Cannot exclude unrelated prefixes  
  - Misconfiguration causes initialization failure

CarbolicAcid aims to be:

- **Explicit in behavior**  
- **Honest about safety**  
- **Zero‑tolerance for misconfiguration**  
- **Lightweight and predictable for ISP/high‑load environments**

If unsure, test your Corefile in a staging environment before deploying to production.
