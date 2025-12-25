package carbolicacid

import (
    "sync"

    "github.com/coredns/caddy"
    "github.com/coredns/coredns/core/dnsserver"
    "github.com/coredns/coredns/plugin"
)

func init() {
    plugin.Register("carbolicacid", setup)
}

func setup(c *caddy.Controller) error {
    cfg, err := parseConfig(c)
    if err != nil {
        return err
    }

    dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
        return &CarbolicAcid{
            Next: next,
            cfg:  cfg,
        }
    })

    return nil
}

type ResponseAction int

const (
    ActionDrop ResponseAction = iota
    ActionServfail
    ActionNxdomain
)

type Config struct {
    Preset       string         // 预设模式："none"（默认）或 "iana"
    ExcludeCIDRs []string       // 用户排除段（任意 CIDR 字符串）
    IncludeCIDRs []string       // 用户追加的投毒段（任意 CIDR 字符串）
    Action       ResponseAction // 毒应答处理策略："drop" | "nxdomain" | "servfail"
    blockList    *IPSet         // 预处理后的结构（全部 bit 化），ServeDNS 直接用它做匹配
    initOnce     sync.Once      // 避免setup()在coredns启动的同时产生大量CIDR初始化计算
    initErr      error
}

func parseConfig(c *caddy.Controller) (*Config, error) {
    cfg := &Config{
        Preset: "none",     // 默认不加载任何预设
        Action: ActionDrop, // v0.3改进：应答处理默认策略
    }

    for c.Next() {
        for c.NextBlock() {
            switch c.Val() {
            case "preset":
                if !c.NextArg() {
                    return nil, c.ArgErr()
                }
                switch c.Val() {
                case "none":
                    cfg.Preset = "none"
                case "iana":
                    cfg.Preset = "iana"
                default:
                    return nil, c.Errf("unknown preset: %s", c.Val())
                }

            case "exclude":
                if !c.NextArg() {
                    return nil, c.ArgErr()
                }
                cfg.ExcludeCIDRs = append(cfg.ExcludeCIDRs, c.Val())

            case "include":
                if !c.NextArg() {
                    return nil, c.ArgErr()
                }
                cfg.IncludeCIDRs = append(cfg.IncludeCIDRs, c.Val())

            case "responses":
                args := c.RemainingArgs()
                if len(args) != 1 {
                    return nil, c.ArgErr()
                }
                switch args[0] {
                case "drop":
                    cfg.Action = ActionDrop
                case "servfail":
                    cfg.Action = ActionServfail
                case "nxdomain":
                    cfg.Action = ActionNxdomain
                default:
                    return nil, c.Errf("invalid responses action: %s", args[0])
                }

            default:
                return nil, c.Errf("unknown directive: %s", c.Val())
            }
        }
    }

    // v0.3.1避免setup()进行CIDR初始化
    // if err := cfg.initBlockList(); err != nil {
        // return nil, err
    // }
    return cfg, nil
}