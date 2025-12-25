package carbolicacid

import "sort"

// 128bit 比较工具
func less128(aHi, aLo, bHi, bLo uint64) bool {
    if aHi < bHi {
        return true
    }
    if aHi > bHi {
        return false
    }
    return aLo < bLo
}

func le128(aHi, aLo, bHi, bLo uint64) bool {
    if aHi < bHi {
        return true
    }
    if aHi > bHi {
        return false
    }
    return aLo <= bLo
}

func ge128(aHi, aLo, bHi, bLo uint64) bool {
    if aHi > bHi {
        return true
    }
    if aHi < bHi {
        return false
    }
    return aLo >= bLo
}

func add128(hi, lo uint64, bits uint8) (uint64, uint64) {
    if bits == 0 {
        lo++
        if lo == 0 {
            hi++
        }
        return hi, lo
    }
    if bits < 64 {
        inc := uint64(1) << bits
        lo += inc
        if lo < inc {
            hi++
        }
        return hi, lo
    }
    incHi := uint64(1) << (bits - 64)
    hi += incHi
    return hi, lo
}

func sub128(hi, lo uint64, bits uint8) (uint64, uint64) {
    if bits == 0 {
        if lo == 0 {
            hi--
        }
        lo--
        return hi, lo
    }
    if bits < 64 {
        dec := uint64(1) << bits
        if lo < dec {
            hi--
        }
        lo -= dec
        return hi, lo
    }
    decHi := uint64(1) << (bits - 64)
    hi -= decHi
    return hi, lo
}

func cidrV6ToRanges(c []IPv6CIDR) []ipv6Range {
    if len(c) == 0 {
        return nil
    }
    out := make([]ipv6Range, 0, len(c))
    for _, v := range c {
        p := v.prefix

        if p == 0 {
            out = append(out, ipv6Range{
                startHi: 0, startLo: 0,
                endHi: ^uint64(0), endLo: ^uint64(0),
            })
            continue
        }

        if p >= 128 {
            out = append(out, ipv6Range{
                startHi: v.shiftedHi, startLo: v.shiftedLo,
                endHi:   v.shiftedHi, endLo:   v.shiftedLo,
            })
            continue
        }

        var startHi, startLo, endHi, endLo uint64

        if p <= 64 {
            // 高 64 位部分前 p bit 固定
            shift := 64 - p
            startHi = v.shiftedHi << shift
            startLo = 0
            endHi = startHi | ((^uint64(0)) >> p) // 后 (64-p) 位全 1
            endLo = ^uint64(0)
        } else {
            // p > 64：高 64 位固定，低 64 位有 (p-64) bit 有效
            lowBits := 128 - p // 低位 block size 的 bit 数
            startHi = v.shiftedHi
            startLo = v.shiftedLo << lowBits
            endHi = startHi
            endLo = startLo | ((^uint64(0)) >> (p - 64))
        }

        out = append(out, ipv6Range{
            startHi: startHi, startLo: startLo,
            endHi:   endHi,   endLo:   endLo,
        })
    }
    return out
}

func mergeIPv6Ranges(in []ipv6Range) []ipv6Range {
    if len(in) == 0 {
        return nil
    }
    sort.Slice(in, func(i, j int) bool {
        return less128(in[i].startHi, in[i].startLo, in[j].startHi, in[j].startLo)
    })
    out := make([]ipv6Range, 0, len(in))
    cur := in[0]
    for i := 1; i < len(in); i++ {
        r := in[i]
        // r.start <= cur.end + 1
        if !less128(cur.endHi, cur.endLo, r.startHi, r.startLo) &&
            !less128(r.startHi, r.startLo, cur.startHi, cur.startLo) {
            // 简化版合并逻辑留给你后面精简，这里先写成直接覆盖
        }
        // 简化：直接用区间重叠判断
        if le128(r.startHi, r.startLo, cur.endHi, cur.endLo+1) {
            // 合并
            if less128(cur.endHi, cur.endLo, r.endHi, r.endLo) {
                cur.endHi, cur.endLo = r.endHi, r.endLo
            }
        } else {
            out = append(out, cur)
            cur = r
        }
    }
    out = append(out, cur)
    return out
}

func diffIPv6Ranges(preset, excl []ipv6Range) []ipv6Range {
    if len(preset) == 0 {
        return nil
    }
    if len(excl) == 0 {
        return preset
    }

    out := make([]ipv6Range, 0, len(preset))
    j := 0

    for _, p := range preset {
        curStartHi, curStartLo := p.startHi, p.startLo
        curEndHi, curEndLo := p.endHi, p.endLo

        // 跳过所有完全在左侧的 exclude: excl[j].end < curStart
        for j < len(excl) && less128(excl[j].endHi, excl[j].endLo, curStartHi, curStartLo) {
            j++
        }

        k := j
        for k < len(excl) && !less128(curEndHi, curEndLo, excl[k].startHi, excl[k].startLo) {
            e := excl[k]

            // 1) exclude 完全覆盖当前区间: e.start <= curStart && e.end >= curEnd
            if !less128(e.startHi, e.startLo, curStartHi, curStartLo) &&
                !less128(curEndHi, curEndLo, e.endHi, e.endLo) {
                // 整段被吃掉
                curStartHi, curStartLo = 1, 0
                curEndHi, curEndLo = 0, 0
                break
            }

            // 2) exclude 覆盖左侧: e.start <= curStart && e.end < curEnd
            if !less128(e.startHi, e.startLo, curStartHi, curStartLo) &&
                less128(e.endHi, e.endLo, curEndHi, curEndLo) {
                // 左边被截断，curStart 移到 e.end + 1
                curStartHi, curStartLo = add128(e.endHi, e.endLo, 0)
            } else if less128(curStartHi, curStartLo, e.startHi, e.startLo) &&
                less128(e.endHi, e.endLo, curEndHi, curEndLo) {
                // 3) exclude 在中间挖洞: curStart < e.start <= e.end < curEnd
                // 先把左半段 [curStart, e.start-1] 收进去
                holeEndHi, holeEndLo := sub128(e.startHi, e.startLo, 0)
                out = append(out, ipv6Range{
                    startHi: curStartHi, startLo: curStartLo,
                    endHi:   holeEndHi,  endLo:   holeEndLo,
                })
                // 再把 curStart 移到 e.end + 1
                curStartHi, curStartLo = add128(e.endHi, e.endLo, 0)
            } else if less128(curStartHi, curStartLo, e.startHi, e.startLo) &&
                !less128(curEndHi, curEndLo, e.endHi, e.endLo) {
                // 4) exclude 覆盖右侧: curStart < e.start && e.end >= curEnd
                // 截断右边: curEnd = e.start - 1
                curEndHi, curEndLo = sub128(e.startHi, e.startLo, 0)
                break
            }

            k++
        }

        // 当前段被完全吃掉
        if !less128(curStartHi, curStartLo, curEndHi, curEndLo) &&
            !(curStartHi == curEndHi && curStartLo == curEndLo) {
            continue
        }

        // 剩余部分加入结果
        out = append(out, ipv6Range{
            startHi: curStartHi, startLo: curStartLo,
            endHi:   curEndHi,   endLo:   curEndLo,
        })
    }

    return out
}

func ipv6RangesToCIDRs(ranges []ipv6Range) []IPv6CIDR {
    var out []IPv6CIDR

    for _, r := range ranges {
        startHi, startLo := r.startHi, r.startLo
        endHi, endLo := r.endHi, r.endLo

        for le128(startHi, startLo, endHi, endLo) {
            // 1) 对齐限制：start 能对齐的最大前缀
            tz := trailingZeros128(startHi, startLo) // 0–128
            alignPrefix := uint8(128 - tz)

            // 2) 长度限制：区间长度能容纳的最大块
            lenHi, lenLo := inclusiveLen128(startHi, startLo, endHi, endLo)
            maxBits := highestBit128(lenHi, lenLo)      // blockSize = 1 << maxBits
            lengthPrefix := uint8(128 - maxBits)        // 对应前缀长度

            // 3) 取两者中“更长的前缀”（更小的块）
            prefix := alignPrefix
            if lengthPrefix > prefix {
                prefix = lengthPrefix
            }

            // 4) 计算 shiftedHi/shiftedLo（预右移）
            var shiftedHi, shiftedLo uint64
            if prefix == 0 {
                shiftedHi, shiftedLo = 0, 0
            } else if prefix <= 64 {
                shiftedHi = startHi >> (64 - prefix)
                shiftedLo = 0
            } else {
                shiftedHi = startHi
                shiftedLo = startLo >> (128 - prefix)
            }

            out = append(out, IPv6CIDR{
                shiftedHi: shiftedHi,
                shiftedLo: shiftedLo,
                prefix:    prefix,
            })

            // 5) 前进到下一个块起点：start += 2^(128 - prefix)
            incBits := uint8(128 - prefix)
            startHi, startLo = add128(startHi, startLo, incBits)
        }
    }

    return out
}

func trailingZeros128(hi, lo uint64) int {
    if hi == 0 && lo == 0 {
        return 128
    }
    if lo != 0 {
        return trailingZeros64(lo)
    }
    return 64 + trailingZeros64(hi)
}

func trailingZeros64(v uint64) int {
    if v == 0 {
        return 64
    }
    n := 0
    for (v & 1) == 0 {
        n++
        v >>= 1
    }
    return n
}

func inclusiveLen128(startHi, startLo, endHi, endLo uint64) (uint64, uint64) {
    // diff = end - start
    var diffHi, diffLo uint64
    if endLo >= startLo {
        diffLo = endLo - startLo
        diffHi = endHi - startHi
    } else {
        diffLo = endLo - startLo
        diffHi = endHi - startHi - 1
    }

    // len = diff + 1
    if diffLo == ^uint64(0) {
        return diffHi + 1, 0
    }
    return diffHi, diffLo + 1
}

func highestBit128(hi, lo uint64) int {
    if hi != 0 {
        return 64 + floorLog2_64(hi)
    }
    return floorLog2_64(lo)
}

func floorLog2_64(v uint64) int {
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
