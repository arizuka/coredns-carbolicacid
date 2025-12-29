package carbolicacid

import (
    "fmt"
    "net"
    "sort"
    "strings"
)

type ipv4Range struct {
    start uint32
    end   uint32
}

type ipv6Range struct {
    startHi, startLo uint64
    endHi, endLo     uint64
}

// 解析 Corefile/手写 CIDR 字符串 → CIDRSet（bit）
// parseCIDRs v0.3.2（保留原逻辑）
func parseCIDRs(list []string) *CIDRSet {
    cs := &CIDRSet{}

    for _, raw := range list {
        s := raw

        // 自动补全掩码
        if !strings.Contains(s, "/") {
            ip := net.ParseIP(s)
            if ip == nil {
                continue
            }
            if ip.To4() != nil {
                s = s + "/32"
            } else {
                s = s + "/128"
            }
        }

        ip, ipNet, err := net.ParseCIDR(s)
        if err != nil {
            continue
        }

        ones, bits := ipNet.Mask.Size()
        if bits != 32 && bits != 128 {
            continue
        }
        if ones < 0 || ones > bits {
            continue
        }

        // IPv4
        if ip4 := ip.To4(); ip4 != nil {
            v := ipv4ToUint32(ip4)
            shift := uint8(32 - ones)
            shifted := v >> shift
            cs.v4 = append(cs.v4, IPv4CIDR{
                shifted: shifted,
                shift:   shift,
            })
            continue
        }

        // IPv6
        hi, lo := ipv6ToUint128(ip)
        p := uint8(ones)

        var shiftedHi, shiftedLo uint64
        if p == 0 {
            shiftedHi, shiftedLo = 0, 0
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

    return cs
}

// ---------------------------
// v0.3.3 严格模式 + 双表模型
// ---------------------------
//
// - 仅支持新语法（preset/block）
// - exclude 必须是父 CIDR 的真子集
// - 所有 exclude 合并为 allowList
// - 所有 preset/block 合并为 blockList
//
func (c *Config) initBlockList() error {
    if len(c.Blocks) == 0 {
        return fmt.Errorf("carbolicacid: no preset/block configured")
    }

    var globalBlock CIDRSet
    var allExcl []string

    for _, b := range c.Blocks {
        switch b.Kind {

        // -------------------------
        // preset iana { exclude ... }
        // preset allip { exclude ... }
        // preset none {}
        // -------------------------
        case RulePreset:
            presetSet, err := loadPresetBit(b.Value)
            if err != nil {
                return err
            }
            globalBlock.v4 = append(globalBlock.v4, presetSet.v4...)
            globalBlock.v6 = append(globalBlock.v6, presetSet.v6...)

            // 父 CIDR 列表
            var parentCIDRs []string
            switch b.Value {
            case "iana":
                parentCIDRs = append(parentCIDRs, ianaPresetV4...)
                parentCIDRs = append(parentCIDRs, ianaPresetV6...)
            case "allip":
                parentCIDRs = append(parentCIDRs, "0.0.0.0/0", "::/0")
            case "none":
                if len(b.Excl) > 0 {
                    return fmt.Errorf("preset 'none' cannot have excludes")
                }
            default:
                return fmt.Errorf("unknown preset: %s", b.Value)
            }

            // exclude 必须是 preset 的子集
            for _, ex := range b.Excl {
                ok, err := cidrSubsetOfAny(ex, parentCIDRs)
                if err != nil {
                    return err
                }
                if !ok {
                    return fmt.Errorf("exclude %q is not subset of preset %q", ex, b.Value)
                }
                allExcl = append(allExcl, ex)
            }

        // -------------------------
        // block CIDR { exclude ... }
        // -------------------------
        case RuleInclude:
            blockSet := parseCIDRs([]string{b.Value})
            globalBlock.v4 = append(globalBlock.v4, blockSet.v4...)
            globalBlock.v6 = append(globalBlock.v6, blockSet.v6...)

            parentCIDRs := []string{b.Value}

            for _, ex := range b.Excl {
                ok, err := cidrSubsetOfAny(ex, parentCIDRs)
                if err != nil {
                    return err
                }
                if !ok {
                    return fmt.Errorf("exclude %q is not subset of block %q", ex, b.Value)
                }
                allExcl = append(allExcl, ex)
            }

        default:
            return fmt.Errorf("unsupported block kind: %v", b.Kind)
        }
    }

    // 构建 blockList
    c.blockList = buildIPSet(&globalBlock)

    // 构建 allowList
    if len(allExcl) > 0 {
        exclSet := parseCIDRs(allExcl)
        c.allowList = buildIPSet(exclSet)
    } else {
        c.allowList = nil
    }

    return nil
}

// ---------------------------
// exclude 子集检查
// ---------------------------
func cidrSubsetOfAny(child string, parents []string) (bool, error) {
    _, childNet, err := net.ParseCIDR(child)
    if err != nil {
        return false, fmt.Errorf("invalid exclude CIDR %q: %v", child, err)
    }

    for _, ps := range parents {
        _, parentNet, err := net.ParseCIDR(ps)
        if err != nil {
            continue
        }

        pOnes, _ := parentNet.Mask.Size()
        cOnes, _ := childNet.Mask.Size()

        if pOnes <= cOnes && parentNet.Contains(childNet.IP) {
            return true, nil
        }
    }

    return false, nil
}

// ---------------------------
// 构建 IPSet（v4 分桶 + v6 原样）
// ---------------------------
func buildIPSet(c *CIDRSet) *IPSet {
    var out IPSet

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

    sort.Slice(out.v4.p8, func(i, j int) bool { return out.v4.p8[i].shifted < out.v4.p8[j].shifted })
    sort.Slice(out.v4.p16, func(i, j int) bool { return out.v4.p16[i].shifted < out.v4.p16[j].shifted })
    sort.Slice(out.v4.p24, func(i, j int) bool { return out.v4.p24[i].shifted < out.v4.p24[j].shifted })
    sort.Slice(out.v4.rest, func(i, j int) bool { return out.v4.rest[i].shifted < out.v4.rest[j].shifted })

    out.v6 = c.v6

    return &out
}