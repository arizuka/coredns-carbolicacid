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

type RuleKind int

const (
    RulePreset RuleKind = iota
    RuleInclude // 用于 block
)

const (
    ActionDrop ResponseAction = iota
    ActionServfail
    ActionNxdomain
    ActionBypass // v0.3.3: 透传但记录告警
)

// v0.3.3 新语法：结构化 preset/block 节点
type BlockNode struct {
    Kind  RuleKind // RulePreset 或 RuleInclude（block）
    Value string   // preset 名称或 CIDR
    Excl  []string // exclude 列表
}

type Config struct {
    Action ResponseAction

    // v0.3.3 新语法：结构化 block/preset
    Blocks []*BlockNode

    // 运行时结构：双表模型
    blockList *IPSet
    allowList *IPSet

    initOnce sync.Once
    initErr  error
}

func parseConfig(c *caddy.Controller) (*Config, error) {
    cfg := &Config{
        Action: ActionDrop,
    }

    for c.Next() {
        for c.NextBlock() {
            switch c.Val() {

            // -------------------------
            // preset iana { exclude ... }
            // preset iana
            // -------------------------
            case "preset":
                args := c.RemainingArgs()
                if len(args) != 1 {
                    return nil, c.ArgErr()
                }
                name := args[0]

                node := &BlockNode{
                    Kind:  RulePreset,
                    Value: name,
                }

                // 尝试读取内层 block：preset NAME { ... }
                if c.NextBlock() {
                    for {
                        switch c.Val() {
                        case "exclude":
                            exArgs := c.RemainingArgs()
                            if len(exArgs) != 1 {
                                return nil, c.ArgErr()
                            }
                            node.Excl = append(node.Excl, exArgs[0])

                        default:
                            return nil, c.Errf("unknown directive %q inside preset %q", c.Val(), name)
                        }

                        if !c.NextBlock() {
                            break
                        }
                    }
                }

                // 无内层 block → 等价于 preset name {}
                cfg.Blocks = append(cfg.Blocks, node)

            // -------------------------
            // block CIDR { exclude ... }
            // block CIDR
            // -------------------------
            case "block":
                args := c.RemainingArgs()
                if len(args) != 1 {
                    return nil, c.ArgErr()
                }
                cidr := args[0]

                node := &BlockNode{
                    Kind:  RuleInclude,
                    Value: cidr,
                }

                if c.NextBlock() {
                    for {
                        switch c.Val() {
                        case "exclude":
                            exArgs := c.RemainingArgs()
                            if len(exArgs) != 1 {
                                return nil, c.ArgErr()
                            }
                            node.Excl = append(node.Excl, exArgs[0])

                        default:
                            return nil, c.Errf("unknown directive %q inside block %q", c.Val(), cidr)
                        }

                        if !c.NextBlock() {
                            break
                        }
                    }
                }

                cfg.Blocks = append(cfg.Blocks, node)

            // -------------------------
            // responses drop|servfail|nxdomain|bypass
            // -------------------------
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
                case "bypass":
                    cfg.Action = ActionBypass
                default:
                    return nil, c.Errf("invalid responses action: %s", args[0])
                }

            default:
                return nil, c.Errf("unknown directive: %s", c.Val())
            }
        }
    }

    return cfg, nil
}