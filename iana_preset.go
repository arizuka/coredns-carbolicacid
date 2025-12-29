package carbolicacid

import "fmt"

// Source webpage: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
var ianaPresetV4 = []string{
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
}

// Source webpage: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
var ianaPresetV6 = []string{
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "100::/64",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
}

func loadPresetBit(name string) (*CIDRSet, error) {
    cs := &CIDRSet{}

    switch name {
    case "none":
        return cs, nil

    case "iana":
        v4 := parseCIDRs(ianaPresetV4)
        // if err != nil { return nil, err }
        v6 := parseCIDRs(ianaPresetV6)
        // if err != nil { return nil, err }
        cs.v4 = append(cs.v4, v4.v4...)
        cs.v6 = append(cs.v6, v6.v6...)
        return cs, nil

    case "allip":
        // v0.3.2 新增 preset：全网匹配
        // 等价于 include 0.0.0.0/0 + include ::/0
        v4 := parseCIDRs([]string{"0.0.0.0/0"})
        v6 := parseCIDRs([]string{"::/0"})
        cs.v4 = append(cs.v4, v4.v4...)
        cs.v6 = append(cs.v6, v6.v6...)
        return cs, nil

    default:
        return nil, fmt.Errorf("unknown preset: %s", name)
    }
}