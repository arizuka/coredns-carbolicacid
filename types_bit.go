package carbolicacid

import "net"

// IPv4CIDR: shifted = base >> shift，shift = 32 - prefix
type IPv4CIDR struct {
    shifted uint32
    shift   uint8
}

// IPv6CIDR: shiftedHi/shiftedLo 预右移，高效匹配
type IPv6CIDR struct {
	shiftedHi uint64
	shiftedLo uint64
	prefix    uint8 // 0–128
}

// CIDRSet: 初始化阶段使用
type CIDRSet struct {
    v4 []IPv4CIDR
    v6 []IPv6CIDR
}

// IPv4PrefixBuckets: 按常见前缀分类的桶，ServeDNS 热点路径使用
type IPv4PrefixBuckets struct {
    p8   []IPv4CIDR
    p16  []IPv4CIDR
    p24  []IPv4CIDR
    rest []IPv4CIDR
}

// IPSet: ServeDNS 热点路径使用
type IPSet struct {
    v4 IPv4PrefixBuckets
    v6 []IPv6CIDR
}

// ----------------- 工具函数（初始化用） -----------------
// IP地址在DNS应答报文中以大端格式表达
func ipv4ToUint32(ip net.IP) uint32 {
    v4 := ip.To4()
    return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

func ipv6ToUint128(ip net.IP) (hi, lo uint64) {
    v6 := ip.To16()
    hi = uint64(v6[0])<<56 | uint64(v6[1])<<48 | uint64(v6[2])<<40 | uint64(v6[3])<<32 |
        uint64(v6[4])<<24 | uint64(v6[5])<<16 | uint64(v6[6])<<8 | uint64(v6[7])
    lo = uint64(v6[8])<<56 | uint64(v6[9])<<48 | uint64(v6[10])<<40 | uint64(v6[11])<<32 |
        uint64(v6[12])<<24 | uint64(v6[13])<<16 | uint64(v6[14])<<8 | uint64(v6[15])
    return
}