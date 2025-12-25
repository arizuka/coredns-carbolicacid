package carbolicacid

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
    if name != "iana" {
        return cs, nil
    }

    v4, err := parseCIDRs(ianaPresetV4)
    if err != nil {
        return nil, err
    }
    v6, err := parseCIDRs(ianaPresetV6)
    if err != nil {
        return nil, err
    }

    cs.v4 = append(cs.v4, v4.v4...)
    cs.v6 = append(cs.v6, v6.v6...)
    return cs, nil
}