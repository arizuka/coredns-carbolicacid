# CarbolicAcid (v0.3.1)

> Named in tribute to Joseph Lister, who introduced **carbolic acid** for surgical disinfection in 1865.
> CarbolicAcid is a CoreDNS plugin that filters DNS responses containing **poisoned IP addresses**, preventing them from reaching clients or entering the CoreDNS cache.

Examples of poisoned IPs:

- 127.0.0.1
- other commonly abused ranges

The plugin supports three response strategies:

- **drop** — silently discard the response  
- **servfail** — return `SERVFAIL`  
- **nxdomain** — return `NXDOMAIN`  

An optional **IANA reserved-range preset** is available.

Blacklist construction:

```
final = preset − exclude + include
```

CarbolicAcid is intentionally **old-school**:
no exceptions, no heuristics, no “smart” behavior, no safety nets.
It filters **only** by IP/CIDR in DNS answers.
It does **not** inspect domain names, DNSSEC, or multi-record logic.
It does **not** try to protect you from yourself.

If you misconfigure it, it will do exactly what you told it to do —
even if that means breaking your system.

---

# 0. ⚠ System Compatibility Warning

CarbolicAcid is a **pure response filter**.
It does not know which domains your OS depends on.
It does not automatically whitelist anything.
It does not try to prevent self-inflicted damage.

If you block DNS answers that your operating system relies on,
you may experience severe system malfunction.

Think of it like the old DOS days:
one stray write into low memory could quietly overwrite anything,
including the in-memory image of IO.SYS/IBMBIO.COM or MSDOS.SYS/IBMDOS.COM,
and the machine would quietly slide into a half-dead state
until you reached for the power switch.

CarbolicAcid behaves the same way —
**absolute power, zero guardrails**.

The following sections explain why.

---

# 0.1 ⚠ Windows (Most Critical)

Windows performs a surprising number of DNS lookups during:

- system startup
- service initialization
- network stack activation
- WinHTTP initialization
- certificate chain validation
- NCSI connectivity checks
- WPAD auto-proxy discovery
- IPv6 reverse lookups

If these queries fail, Windows may enter a **half-frozen state**:

- UI becomes unresponsive
- physical keyboard/mouse stop responding
- Remote Desktop disconnects
- services fail to start
- DNS Client hangs
- network I/O partially stalls

After several minutes, Windows may “thaw out” —
but during the freeze, even logging subsystems are silent.

### Why this happens

Windows resolves its own hostname as a **FQDN**, not as a bare name.

Example:

```
hostname → hostname.<search-domain>
```

This FQDN **must** be answered correctly by the DNS server.  
If CarbolicAcid blocks the answer (e.g., because it contains 127.0.0.1),
Windows may deadlock during boot.

You can check the server hostname via:

- `hostname`  
- `echo %COMPUTERNAME%`  
- `$env:COMPUTERNAME`  

### Important

Even if the server itself points its DNS to some upstream resolver,  
**clients on the LAN will still send**:

```
terminal-hostname.<search-domain>
```

to **your CoreDNS instance**, not to the upstream.  
If your CoreDNS root zone filters 127.0.0.1,  
these queries will be blocked, and Windows clients may freeze.

### Recommended mitigation

Create a **dedicated authoritative zone** for the server’s own hostname:

```
"your-server-hostname" {
    # enable at least one plugin to activate the zone
    log
}
```

This ensures the server’s own FQDN is answered locally  
and never falls through to the root zone where CarbolicAcid is active.

---

# 0.2 Linux / BSD / Solaris (Lower Risk)

UNIX-like systems typically resolve:

- `localhost`  
- `::1`  
- the system hostname  

via `/etc/hosts`, not DNS.

However, if `nsswitch.conf` contains:

```
hosts: dns files
```

then DNS lookups may occur during boot.

### Possible DNS lookups

- `localhost` / `::1`  
- the system hostname  
- `.local` (mDNS)  

### Where hostnames are stored

**Linux (systemd)**  
- `/etc/hostname`  
- `/etc/hosts`  
- `hostnamectl`

**Linux (SysV)**  
- `/etc/sysconfig/network`  
- `/etc/HOSTNAME`

**FreeBSD / OpenBSD / NetBSD**  
- `/etc/rc.conf` (`hostname="foo.example.com"`)  
- `/etc/hosts`

**OpenIndiana / illumos / Solaris**  
- `/etc/nodename`  
- `/etc/hosts`

Blocking these queries may cause delays,  
but typically not full system lockups.

### Recommended mitigation

- Ensure `/etc/hosts` contains both `localhost` and the hostname  
- Avoid filtering `127.0.0.1` and `::1`  
- Or isolate the server’s own hostname in a dedicated zone

---

# 0.3 Summary

To safely use CarbolicAcid:

- You **must** create a dedicated zone for the DNS server’s own hostname  
- This zone must contain **at least one plugin** (e.g., `log`)  
- Otherwise CoreDNS treats it as empty and falls back to the root zone  
- The root zone is where CarbolicAcid is active  
- If the hostname falls into the root zone,  
  you may experience **Carbolic-acid-style DNS sterilization**  
  — a system so clean that even its own DNS can’t survive

Example (do not copy blindly):

```
"your-server-hostname" {
    # activate this zone so it does NOT fall through to the root zone
    log
}

. {
    forward . 1.1.1.1
    carbolicacid {
        # enable filtering here
        preset iana

        # do NOT allow 127.0.0.1/32 unless you know exactly what you are doing
        # exclude 127.0.0.1/32 if you really need to
    }
}

```

Notes:

- CoreDNS treats "your-server-hostname" as a complete domain name and creates an authoritative zone for it. Just fill in the actual hostname (as a full FQDN) that clients will resolve on your network.
- DNS is case-insensitive; CoreDNS normalizes names to lowercase  
- The example above is conceptual — users must substitute their actual hostname

---

# 1. Minimal configuration

```
carbolicacid
```

Equivalent to:

```
carbolicacid {
    preset none
    responses drop
}
```

---

# 2. Use the IANA preset blacklist

```
carbolicacid {
    preset iana
}
```

---

# 3. Add custom blacklist entries

```
carbolicacid {
    include 198.51.100.0/24
}
```

---

# 4. Exclude specific ranges

```
carbolicacid {
    preset iana
    exclude 169.254.0.0/16
}
```
exclude only removes addresses from an existing set,
it cannot remove CIDRs from an empty set, and it does not create a whitelist by itself.

In other words:
- exclude must operate after a preset or an include.
- You cannot start with exclude alone.
- Excluding a range without a prior base set has no effect.

---

# 5. Response actions (v0.3.1)

```
responses drop
responses servfail
responses nxdomain
```

---

# 6. Default behavior

| Option    | Default | Description                    |
| --------- | ------- | ------------------------------ |
| preset    | none    | No preset blacklist            |
| responses | drop    | Poisoned responses are dropped |
| include   | empty   | No additional CIDRs            |
| exclude   | empty   | No CIDRs removed               |

---

# 7. Full configuration syntax

```
carbolicacid {
    preset [none|iana]
    exclude CIDR
    include CIDR
    responses [drop|servfail|nxdomain]
}
```

---

# 8. Known limitations

- CIDRs **must** include a mask;  
  `127.0.0.1` is **not** equivalent to `127.0.0.1/32`  
- The blacklist is constructed in a fixed order:  
  `preset → exclude → include`  
  You cannot include a large range and then exclude a smaller sub-range
