package carbolicacid

import (
    "net"
    "sort"
)

// 解析 Corefile/手写 CIDR 字符串 → CIDRSet（bit）
func parseCIDRs(list []string) (*CIDRSet, error) {
    cs := &CIDRSet{}
    for _, s := range list {
        ip, ipNet, err := net.ParseCIDR(s)
        if err != nil {
            return nil, err
        }
        ones, _ := ipNet.Mask.Size()

		if ip4 := ip.To4(); ip4 != nil {
    		v := ipv4ToUint32(ip4)
    		shift := uint8(32 - ones)
    		shifted := v >> shift
    		cs.v4 = append(cs.v4, IPv4CIDR{
        		shifted: shifted,
        		shift:   shift,
    		})
		} else {
    		hi, lo := ipv6ToUint128(ip)
    		p := uint8(ones)
    		var shiftedHi, shiftedLo uint64
    		if p == 0 {
        		shiftedHi, shiftedLo = 0, 0 // 全网匹配
    		} else if p <= 64 {
        		shiftedHi = hi >> (64 - p)
        		shiftedLo = 0
    		} else {
        		shiftedHi = hi
        		shiftedLo = lo >> (128 - p)
    		}
    		cs.v6 = append(cs.v6, IPv6CIDR{
        		shiftedHi: shiftedHi,
        		shiftedLo: shiftedLo,
        		prefix:    p,
    		})
		}
    }
    return cs, nil
}

// initBlockList: preset - exclude + include → IPSet（bit）
func (c *Config) initBlockList() error {
    var presetSet *CIDRSet
    var err error

    if c.Preset == "none" {
        presetSet = &CIDRSet{}
    } else {
        presetSet, err = loadPresetBit(c.Preset)
        if err != nil {
            return err
        }
    }

    exclSet, err := parseCIDRs(c.ExcludeCIDRs)
    if err != nil {
        return err
    }
    inclSet, err := parseCIDRs(c.IncludeCIDRs)
    if err != nil {
        return err
    }

    // preset - exclude
    sub := subtractCIDRs(presetSet, exclSet)
    // + include
    final := &CIDRSet{
        v4: append(sub.v4, inclSet.v4...),
        v6: append(sub.v6, inclSet.v6...),
    }

    c.blockList = buildIPSet(final)
    return nil
}

// buildIPSet: 将 CIDRSet 转换为按前缀分类的 IPSet（仅对 IPv4 做分桶）
func buildIPSet(c *CIDRSet) *IPSet {
    var out IPSet

    // IPv4: 按常见前缀 /8 /16 /24 分桶，其余放到 rest
    for _, v := range c.v4 {
        switch v.shift {
        case 24:
            out.v4.p8 = append(out.v4.p8, v)
        case 16:
            out.v4.p16 = append(out.v4.p16, v)
        case 8:
            out.v4.p24 = append(out.v4.p24, v)
        default:
            out.v4.rest = append(out.v4.rest, v)
        }
    }

    // v0.3：cache locality patch —— 对每个 bucket 排序
    sort.Slice(out.v4.p8, func(i, j int) bool {
        return out.v4.p8[i].shifted < out.v4.p8[j].shifted
    })
    sort.Slice(out.v4.p16, func(i, j int) bool {
        return out.v4.p16[i].shifted < out.v4.p16[j].shifted
    })
    sort.Slice(out.v4.p24, func(i, j int) bool {
        return out.v4.p24[i].shifted < out.v4.p24[j].shifted
    })
    sort.Slice(out.v4.rest, func(i, j int) bool {
        return out.v4.rest[i].shifted < out.v4.rest[j].shifted
    })

    // IPv6 不排序
    out.v6 = c.v6

    return &out
}

// ---------------------- subtractCIDRs (bit-only) ----------------------

type ipv4Range struct {
    start uint32
    end   uint32
}

type ipv6Range struct {
    startHi, startLo uint64
    endHi, endLo     uint64
}

func subtractCIDRs(preset, excl *CIDRSet) *CIDRSet {
    out := &CIDRSet{}
    // IPv4
    presetR := cidrV4ToRanges(preset.v4)
    exclR := cidrV4ToRanges(excl.v4)
    mergedPreset := mergeIPv4Ranges(presetR)
    mergedExcl := mergeIPv4Ranges(exclR)
    kept := diffIPv4Ranges(mergedPreset, mergedExcl)
    out.v4 = ipv4RangesToCIDRs(kept)

    // IPv6（可以先留 TODO，或者只实现前缀<=64的简化版）
    presetR6 := cidrV6ToRanges(preset.v6)
    exclR6 := cidrV6ToRanges(excl.v6)
    mergedPreset6 := mergeIPv6Ranges(presetR6)
    mergedExcl6 := mergeIPv6Ranges(exclR6)
    kept6 := diffIPv6Ranges(mergedPreset6, mergedExcl6)
    out.v6 = ipv6RangesToCIDRs(kept6)

    return out
}

// ---------------------- IPv4: CIDR <-> ranges ----------------------
func cidrV4ToRanges(c []IPv4CIDR) []ipv4Range {
    if len(c) == 0 {
        return nil
    }

    out := make([]ipv4Range, 0, len(c))

    for _, v := range c {
        base := v.shifted << v.shift

        if v.shift == 0 {
            out = append(out, ipv4Range{start: base, end: base})
            continue
        }

        size := uint32(1) << v.shift
        start := base
        end := start + size - 1

        out = append(out, ipv4Range{start: start, end: end})
    }

    return out
}

func mergeIPv4Ranges(in []ipv4Range) []ipv4Range {
    if len(in) == 0 {
        return nil
    }
    sort.Slice(in, func(i, j int) bool {
        return in[i].start < in[j].start
    })
    out := make([]ipv4Range, 0, len(in))
    cur := in[0]
    for i := 1; i < len(in); i++ {
        r := in[i]
        if r.start <= cur.end+1 {
            if r.end > cur.end {
                cur.end = r.end
            }
        } else {
            out = append(out, cur)
            cur = r
        }
    }
    out = append(out, cur)
    return out
}

func diffIPv4Ranges(preset, excl []ipv4Range) []ipv4Range {
    if len(preset) == 0 {
        return nil
    }
    if len(excl) == 0 {
        return preset
    }

    out := make([]ipv4Range, 0, len(preset))
    j := 0
    for _, p := range preset {
        curStart := p.start
        curEnd := p.end

        for j < len(excl) && excl[j].end < curStart {
            j++
        }
        k := j
        for k < len(excl) && excl[k].start <= curEnd {
            e := excl[k]

            if e.start <= curStart && e.end >= curEnd {
                curStart = 1
                curEnd = 0
                break
            }

            if e.start <= curStart && e.end < curEnd {
                curStart = e.end + 1
            } else if e.start > curStart && e.end < curEnd {
                out = append(out, ipv4Range{start: curStart, end: e.start - 1})
                curStart = e.end + 1
            } else if e.start > curStart && e.start <= curEnd && e.end >= curEnd {
                curEnd = e.start - 1
                break
            }
            k++
        }

        if curStart <= curEnd {
            out = append(out, ipv4Range{start: curStart, end: curEnd})
        }
    }
    return out
}

func ipv4RangesToCIDRs(ranges []ipv4Range) []IPv4CIDR {
    var out []IPv4CIDR
    for _, r := range ranges {
        start := r.start
        end := r.end

        for start <= end {
            maxSize := trailingZeros32(start)
            remaining := end - start + 1
            maxBlock := 31 - floorLog2(remaining)

            var prefix uint32
            if maxSize < maxBlock {
                prefix = 32 - uint32(maxSize)
            } else {
                prefix = 32 - uint32(maxBlock)
            }

			shift := uint8(32 - prefix)
			shifted := start >> shift
			out = append(out, IPv4CIDR{
    			shifted: shifted,
    			shift:   shift,
			})

			blockSize := uint32(1) << shift
			start += blockSize
        }
    }
    return out
}

func trailingZeros32(v uint32) int {
    if v == 0 {
        return 32
    }
    n := 0
    for (v & 1) == 0 {
        n++
        v >>= 1
    }
    return n
}

func floorLog2(v uint32) int {
    if v == 0 {
        return 0
    }
    n := 0
    for v > 1 {
        v >>= 1
        n++
    }
    return n
}