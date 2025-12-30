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

// ServeDNS: v0.3.4 严格模式 + 显式短路 + allowList 优先
func (c *CarbolicAcid) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    // 初始化 blockList + allowList（只执行一次）
    c.cfg.initOnce.Do(func() {
        c.cfg.initErr = c.cfg.initBlockList()
    })

    // 初始化失败 → 整个插件 bypass
    if c.cfg.initErr != nil {
        log.Errorf("[carbolicacid] init failed: %v, fallback to BYPASS mode", c.cfg.initErr)
        return plugin.NextOrFailure(c.Name(), c.Next, ctx, w, r)
    }

    // 截获上游响应
    rw := &respRecorder{ResponseWriter: w}
    rc, err := plugin.NextOrFailure(c.Name(), c.Next, ctx, rw, r)
    if err != nil {
        return rc, err
    }

    resp := rw.msg
    if resp == nil {
        return rc, nil // 上游无响应
    }

    // ---------------------------------------------------------
    // 1) allowList 优先（仅当 allowList 存在时）
    // ---------------------------------------------------------
    if c.cfg.allowList != nil {
        if c.cfg.allowList.HasAny(resp) {
            w.WriteMsg(resp)
            return rc, nil
        }
    }

    // ---------------------------------------------------------
    // 2) preset = allip → 进入“全阻断模式”
    //
    //    - allowList 存在且命中 → 已在上面放行
    //    - allowList 不存在 或 未命中 → 必须阻断
    //    - blockList 永远跳过
    // ---------------------------------------------------------
    if c.cfg.presetAllIP {
        switch c.cfg.Action {
        case ActionDrop:
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
            w.WriteMsg(resp)
            return rc, nil
        }
    }

    // ---------------------------------------------------------
    // 3) preset ≠ allip → 正常双表模型
    //
    //    - allowList 已经在上面检查过
    //    - blockList 命中 → 阻断
    //    - 否则 → 放行
    // ---------------------------------------------------------
    if c.cfg.blockList != nil && c.cfg.blockList.HasAny(resp) {
        switch c.cfg.Action {
        case ActionDrop:
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
            w.WriteMsg(resp)
            return rc, nil
        }
    }

    // ---------------------------------------------------------
    // 4) 未命中任何表 → 正常返回上游响应
    // ---------------------------------------------------------
    w.WriteMsg(resp)
    return rc, nil
}