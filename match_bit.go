package carbolicacid

import (
    "net"
    "github.com/miekg/dns"
)

func containsPoisonedIP(resp *dns.Msg, set *IPSet) bool {
    if set == nil {
        return false
    }
    if len(resp.Answer) == 0 {
        return false
    }

    for _, rr := range resp.Answer {
        switch a := rr.(type) {
        case *dns.A:
            ip := ipv4ToUint32(a.A)
            if matchIPv4(ip, set.v4) {
                return true
            }
        case *dns.AAAA:
            hi, lo := ipv6ToUint128(net.IP(a.AAAA))
            if matchIPv6(hi, lo, set.v6) {
                return true
            }
        }
    }
    return false
}

// ---------------- IPv4: prefix buckets fast path ----------------
func matchIPv4(ip uint32, buckets IPv4PrefixBuckets) bool {
    ip8 := ip >> 24
    ip16 := ip >> 16
    ip24 := ip >> 8

    // /8 bucket（shift=24）
    for i := range buckets.p8 {
        v := &buckets.p8[i]
        if ip8 == v.shifted {
            return true
        }
    }

    // /16 bucket（shift=16）
    for i := range buckets.p16 {
        v := &buckets.p16[i]
        if ip16 == v.shifted {
            return true
        }
    }

    // /24 bucket（shift=8）
    for i := range buckets.p24 {
        v := &buckets.p24[i]
        if ip24 == v.shifted {
            return true
        }
    }

    // 其他前缀 fallback：通用匹配 (ip >> shift) == shifted
    for i := range buckets.rest {
        v := &buckets.rest[i]
        if (ip >> v.shift) == v.shifted {
            return true
        }
    }

    return false
}

// ---------------- IPv6: shifted-only ----------------
// (p <= 64) → bool → 0/1
// (p > 64) → bool → 0/1
// (v1 == 0) → bool → 0/1
// (v2 == 0) → bool → 0/1
func matchIPv6(hi, lo uint64, nets []IPv6CIDR) bool {
    for i := range nets {
        n := &nets[i]
        p := uint64(n.prefix)

        // prefix <= 64 → mask1 = 1
        // prefix > 64  → mask2 = 1
        mask1 := uint64((p - 1) >> 63)        // p==0 → mask1=1；p>=1 → mask1=0
        mask2 := uint64(((64 - p) >> 63) & 1) // p>64 → mask2=1

        // hi-match
        shift1 := 64 - p
        v1 := ((hi >> shift1) ^ n.shiftedHi) | (mask1 ^ 1)

        // lo-match
        shift2 := 128 - p
        v2 := ((lo >> shift2) ^ n.shiftedLo) | (mask2 ^ 1) | ((hi ^ n.shiftedHi) & mask2)

        // 命中：v1 == 0 或 v2 == 0
        if v1 == 0 || v2 == 0 {
            return true
        }
    }
    return false
}