# **CarbolicAcid (v0.3.3)**
CarbolicAcid is a CoreDNS plugin for filtering poisoned DNS responses.

> Named in tribute to Joseph Lister, the British surgeon who first used **carbolic acid** for surgical antisepsis in 1865.  
> CarbolicAcid is a CoreDNS plugin designed to intercept DNS responses containing **poisoned IP addresses** and prevent them from entering the CoreDNS cache.  
> Examples of poisoned IPs include:

- `127.0.0.1`
- Private networks such as `10.0.0.0/8` or `192.168.0.0/16`
- `::1`
- `100::/64` (blackhole)
- Other commonly abused ranges

Supported response actions (v0.3.3):

- `drop` — silently discard the response  
- `servfail` — return `SERVFAIL`  
- `nxdomain` — return `NXDOMAIN`  
- `bypass` — pass upstream response through unchanged (audit-only)

CarbolicAcid uses a **dual-table model** inside each plugin instance:

- A **blockList** (blacklist)
- An **allowList** (whitelist)

Rules:

- `preset iana` loads IANA-defined special-use and reserved prefixes  
  (IPv4: https://www.iana.org/assignments/iana-ipv4-special-registry/  
   IPv6: https://www.iana.org/assignments/iana-ipv6-special-registry/)
- `preset allip` loads `0.0.0.0/0` and `::/0` (treat all IPs as blockable)
- `block` appends prefixes to the blockList
- `exclude` extracts sub-prefixes from its **parent rule** (preset or block) and places them into the allowList  
  (must be a strict subnet of the parent; otherwise initialization fails)

Matching logic:

- **allowList has priority** — if any A/AAAA record matches allowList, the entire response is allowed  
- Otherwise, if any A/AAAA record matches blockList, the entire response is treated as poisoned  
- If no `exclude` appears in the instance, allowList is empty and only blockList is used

CarbolicAcid is intentionally designed as a **old-school, assembly-style, non-smart, ISP-grade IP-only filter**:

- It does **not** validate DNSSEC  
- It does **not** filter by domain or FQDN  
- It does **not** guess user intent or auto-correct dangerous configs  
- It does **not** partially filter responses — **one poisoned record poisons the entire response**

Please ensure:

- System-critical DNS names are not accidentally blocked  
- Windows users pay special attention  
- You read this document carefully before deployment

If you enable maximum strictness without proper exclusions, you may experience true **“carbolic-acid-style DNS sterilization”** — so clean that even your system’s own DNS stops working.

---

# **1. ⚠ System Compatibility Warning**

CarbolicAcid is a **pure response filter**:

- Only inspects `A` / `AAAA` records  
- Only matches IPs/CIDRs  
- Only performs the action you configure  
- **No exceptions, no heuristics, no safety nets**

It will **not**:

- Detect dangerous configurations  
- Protect the system from user mistakes  
- Apply “helpful” corrections

Meaning:

> If you block DNS names your system depends on, the system may behave very badly.

If misconfigured:

> You may relive the DOS era where “writing past array bounds kills the whole machine.”

**Read the following sections carefully.**

---

## **1.1 Server FQDN and 127.0.0.1 / ::1**

During boot and hostname resolution, both the OS and LAN clients will query the server’s **own FQDN**.  
These queries **must** be allowed, or you may experience:

- Slow boot  
- Network issues  
- Windows UI freeze or partial deadlock

You must configure the server’s **FQDN** as a dedicated CoreDNS zone, e.g.:

```corefile
"server.example.com" {
    log
}
```

This ensures hostname-related queries do **not** fall into the root zone, where CarbolicAcid may block them.

Notes:

- The server’s FQDN is **not** `localhost`  
- It is **not** the Windows NetBIOS name  
- It is **not** the search-domain  
- In AD or DHCP environments, FQDN = `<hostname>.<domain>`  
- In standalone environments, FQDN = `<hostname>.`

A later section explains how to correctly obtain the FQDN on Windows.

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
- Drop RDP sessions  
- Fail to start services  
- Partially deadlock the DNS Client  
- Become unstable for several minutes

If:

- You enable `preset iana` or block `127.0.0.1/32` / `::1/128`, **and**
- Windows points its DNS to this CoreDNS instance

Then:

> Windows will query system-critical names.  
> If CarbolicAcid blocks them, Windows may freeze or behave unpredictably.

But don’t worry — with enough patience, Windows may eventually unfreeze itself. Until then, even the logging subsystem will remain completely silent. I’ve experienced this myself.

How to obtain the server’s FQDN:

- **Standalone Windows (WORKGROUP):**

  ```powershell
  $env:COMPUTERNAME
  ```

- **Domain-joined Windows:**

  ```powershell
  $env:COMPUTERNAME + "." + (Get-CimInstance Win32_ComputerSystem).Domain
  ```

⚠ Note:  
On standalone Windows, the above command may output `<HOSTNAME>.WORKGROUP`,  
but **WORKGROUP is not a DNS domain** and must not be used as the FQDN.

### Recommended (choose one):

- Create a dedicated zone for the server’s FQDN and **do not** block 127.0.0.1 / ::1 in that zone  
- Point Windows to another DNS server (reduces protection; not recommended)  
- Use `exclude 127.0.0.1/32` and `exclude ::1/128` in the root zone (reduces protection; not recommended)

---

## **1.3 Linux / BSD / Solaris (Lower Risk)**

These systems usually resolve their own hostname via `/etc/hosts`, but if `nsswitch.conf` contains:

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
If no domain exists, the hostname itself is the FQDN.

If CarbolicAcid blocks these lookups:

- Boot may slow down  
- Some services may delay  
- But usually not as severe as Windows

### Recommended:

- Create a dedicated zone for the server’s FQDN  
- Ensure `/etc/hosts` contains hostname → 127.0.0.1 / ::1  
- Or (not recommended) exclude 127.0.0.1 / ::1 in the root zone

---

## **1.4 LAN Clients**

LAN clients generate their own FQDNs by appending the search-domain:

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

Using only a root zone with CarbolicAcid enabled and blocking 127.0.0.1 is almost guaranteed to cause system instability — a true **“carbolic-acid DNS sterilization.”**

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

DNS is case-insensitive but case-preserving.  
CoreDNS normalizes Corefile FQDNs to lowercase.  
**Use lowercase for zone names.**

⚠ Reminder:

```corefile
"your-server-fqdn" {}
```

is an **empty zone**, and CoreDNS will fall back to the root zone —  
meaning your server’s own hostname queries will still be filtered by CarbolicAcid.

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

- No preset blacklist  
- Default action is `drop`  
- With no `block`, nothing is actually blocked

---

# **3. Presets**

## **3.1 preset iana**

```corefile
carbolicacid {
    preset iana
}
```

Loads IANA special-use/reserved prefixes.  
You may refine them:

```corefile
carbolicacid {
    preset iana { exclude 169.254.0.0/16 }
    block 192.88.99.0/24
}
```

Conceptually:

- `preset` and `block` build the blockList  
- `exclude` extracts sub-prefixes into the allowList  
- Matching: allowList → blockList

---

## **3.2 preset allip**

```corefile
carbolicacid {
    preset allip
}
```

Expands to:

- `0.0.0.0/0`
- `::/0`

Meaning: all IPs are blockable unless excluded.

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

---

## **3.3 preset none**

```corefile
carbolicacid {
    preset none
}
```

- No preset blacklist  
- Must use `block` to block anything  
- `preset none` cannot have `exclude`

---

# **4. Custom Block Entries**

```corefile
carbolicacid {
    block 198.51.100.0/24
}
```

v0.3.3:

- CIDR may be explicit (`1.2.3.4/32`)  
- Or implicit (`1.2.3.4` → `/32`, `2001:db8::1` → `/128`)  
- All prefixes validated via `net.ParseCIDR`

---

# **5. exclude and Subset Enforcement**

```corefile
carbolicacid {
    preset iana { exclude 169.254.0.0/16 }
}
```

Rules:

- `exclude` must be a strict subnet of its **parent rule**  
- Cannot exclude from an empty set  
- Cannot exclude a prefix unrelated to the parent  
- Misconfiguration causes **initialization failure**

---

# **6. Response Actions**

- `drop` — discard  
- `servfail` — return SERVFAIL  
- `nxdomain` — return NXDOMAIN  
- `bypass` — pass upstream response unchanged (audit mode)

---

# **7. Defaults**

| Option    | Default | Meaning |
|----------|---------|---------|
| preset    | none | No preset blacklist |
| responses | drop | Drop poisoned responses |
| block     | empty | No custom blocks |
| exclude   | empty | No exclusions |

---

# **8. Full Syntax (v0.3.3)**

```corefile
carbolicacid {
    preset [none|iana|allip] { exclude CIDR }
    block CIDR { exclude CIDR }
    responses [drop|servfail|nxdomain|bypass]
}
```

Rules:

- CIDR may be explicit or implicit (/32 or /128)  
- `preset none` cannot have `exclude`  
- `exclude` must be a subnet of its parent  
- One poisoned record poisons the entire response  
- allowList overrides blockList

---

# **9. Known Behaviors (v0.3.3)**

- Supports automatic mask completion (`1.2.3.4` → `/32`)  
- No partial filtering of responses  
- Only A/AAAA are inspected  
- exclude is strictly constrained  
- Initialization fails on misconfiguration

---

If unsure, test your Corefile in a staging environment before deploying to production.
