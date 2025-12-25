package carbolicacid

import (
    "context"
    
    "github.com/coredns/coredns/plugin"
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
    return nil   // 不透传
}

func (c *CarbolicAcid) Name() string { return "carbolicacid" }

func (c *CarbolicAcid) Ready() bool { return true }

func (c *CarbolicAcid) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    // v0.3.1 lazy init: build blockList on first ServeDNS
    c.cfg.initOnce.Do(func() {
        c.cfg.initErr = c.cfg.initBlockList()
    })
    if c.cfg.initErr != nil {
        // 初始化失败 → 插件降级为透传
        return plugin.NextOrFailure(c.Name(), c.Next, ctx, w, r)
    }

    rec := &respRecorder{ResponseWriter: w}

    rc, err := plugin.NextOrFailure(c.Name(), c.Next, ctx, rec, r)
    if err != nil {
        return rc, err
    }

    resp := rec.msg
    if resp == nil {
        return rc, nil
    }

    if resp.Rcode != dns.RcodeSuccess {
        // 非 NOERROR → 原样返回
        _ = w.WriteMsg(resp)
        return rc, nil
    }

    if len(resp.Answer) == 0 {
        // 无 Answer → 原样返回
        _ = w.WriteMsg(resp)
        return rc, nil
    }

    if !containsPoisonedIP(resp, c.cfg.blockList) {
        // 非毒 → 原样返回
        _ = w.WriteMsg(resp)
        return rc, nil
    }

    switch c.cfg.Action {
    case ActionDrop:
        // 不写回任何响应
        return dns.RcodeSuccess, nil

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
    
    default:
        return dns.RcodeSuccess, nil    //其实还是drop
    }
}