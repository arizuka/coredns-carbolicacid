package carbolicacid

import (
    "context"

    "github.com/coredns/coredns/plugin"
    "github.com/coredns/coredns/plugin/pkg/log"
    "github.com/miekg/dns"
)

type CarbolicAcid struct {
    Next plugin.Handler
    cfg  *Config
}

type respRecorder struct {
    dns.ResponseWriter
    msg *dns.Msg
}

func (r *respRecorder) WriteMsg(m *dns.Msg) error {
    r.msg = m
    // 拦截上游响应，不直接写回客户端
    return nil
}

func (c *CarbolicAcid) Name() string { return "carbolicacid" }

func (c *CarbolicAcid) Ready() bool { return true }

// ServeDNS: v0.3.3 严格模式 + 双表模型 + bypass
func (c *CarbolicAcid) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    // 初始化 blockList + allowList
    c.cfg.initOnce.Do(func() {
        c.cfg.initErr = c.cfg.initBlockList()
    })

    // 初始化失败 → 直接 bypass 整个插件，透传上游行为
    if c.cfg.initErr != nil {
        log.Errorf("[carbolicacid] init failed: %v, fallback to BYPASS mode", c.cfg.initErr)
        return plugin.NextOrFailure(c.Name(), c.Next, ctx, w, r)
    }

    // 用 respRecorder 截获上游响应
    rw := &respRecorder{ResponseWriter: w}
    rc, err := plugin.NextOrFailure(c.Name(), c.Next, ctx, rw, r)
    if err != nil {
        return rc, err
    }

    resp := rw.msg
    if resp == nil {
        // 上游没有返回响应，直接结束
        return rc, nil
    }

    // 先看 allowList：命中则直接放行（即便 blockList 也命中）
    if c.cfg.allowList != nil && c.cfg.allowList.HasAny(resp) {
        w.WriteMsg(resp)
        return rc, nil
    }

    // 再看 blockList：命中则按策略处理
    if c.cfg.blockList != nil && c.cfg.blockList.HasAny(resp) {
        switch c.cfg.Action {
        case ActionDrop:
            // 什么都不写，直接丢弃
            return rc, nil

        case ActionServfail:
            m := new(dns.Msg)
            m.SetRcode(r, dns.RcodeServerFailure)
            w.WriteMsg(m)
            return dns.RcodeServerFailure, nil

        case ActionNxdomain:
            m := new(dns.Msg)
            m.SetRcode(r, dns.RcodeNameError)
            w.WriteMsg(m)
            return dns.RcodeNameError, nil

        case ActionBypass:
            // 记录告警，但透传上游响应
            log.Warningf("[carbolicacid] poisoned response bypassed: %s", r.Question[0].Name)
            w.WriteMsg(resp)
            return rc, nil
        }
    }

    // 未命中任何表 → 正常返回上游响应
    w.WriteMsg(resp)
    return rc, nil
}