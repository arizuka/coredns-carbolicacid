package carbolicacid

import (
    "context"
    "fmt"
    "testing"

    "github.com/miekg/dns"
)

// -------------------------------
// 工具：构造 DNS 响应
// -------------------------------
func makeA(name string, ip string) *dns.Msg {
    m := new(dns.Msg)
    m.SetReply(&dns.Msg{
        Question: []dns.Question{
            {Name: dns.Fqdn(name), Qtype: dns.TypeA},
        },
    })
    rr, _ := dns.NewRR(name + " 60 IN A " + ip)
    m.Answer = append(m.Answer, rr)
    return m
}

// -------------------------------
// mock ResponseWriter
// -------------------------------
type testResponseWriter struct {
    dns.ResponseWriter
    msg *dns.Msg
}

func (w *testResponseWriter) WriteMsg(m *dns.Msg) error {
    w.msg = m
    return nil
}

// -------------------------------
// mock Next plugin
// -------------------------------
type testNext struct {
    resp *dns.Msg
}

func (t *testNext) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    w.WriteMsg(t.resp)
    return dns.RcodeSuccess, nil
}

func (t *testNext) Name() string { return "testNext" }

// -------------------------------
// Test: preset iana
// -------------------------------
func TestPresetIANA(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {Kind: RulePreset, Value: "iana"},
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    resp := makeA("example.com.", "127.0.0.1")

    if !cfg.blockList.HasAny(resp) {
        t.Fatalf("expected 127.0.0.1 to match iana preset")
    }
}

// -------------------------------
// Test: block + exclude
// -------------------------------
func TestBlockWithExclude(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {
                Kind:  RuleInclude,
                Value: "1.2.3.0/24",
                Excl:  []string{"1.2.3.4/32"},
            },
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    resp1 := makeA("example.com.", "1.2.3.5")
    if !cfg.blockList.HasAny(resp1) {
        t.Fatalf("expected 1.2.3.5 to match blockList")
    }

    resp2 := makeA("example.com.", "1.2.3.4")
    if !cfg.allowList.HasAny(resp2) {
        t.Fatalf("expected 1.2.3.4 to match allowList")
    }
}

// -------------------------------
// Test: bypass
// -------------------------------
func TestBypass(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {Kind: RuleInclude, Value: "10.0.0.0/8"},
        },
        Action: ActionBypass,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    upstreamResp := makeA("example.com.", "10.1.2.3")
    next := &testNext{resp: upstreamResp}
    ca := &CarbolicAcid{Next: next, cfg: cfg}

    rw := &testResponseWriter{}
    rc, err := ca.ServeDNS(context.Background(), rw, makeA("example.com.", "8.8.8.8"))
    if err != nil {
        t.Fatalf("ServeDNS error: %v", err)
    }

    if rc != dns.RcodeSuccess {
        t.Fatalf("expected bypass to return upstream RcodeSuccess")
    }

    if rw.msg == nil {
        t.Fatalf("expected bypass to write upstream response")
    }
}

// -------------------------------
// Test: drop
// -------------------------------
func TestDrop(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {Kind: RuleInclude, Value: "10.0.0.0/8"},
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    upstreamResp := makeA("example.com.", "10.1.2.3")
    next := &testNext{resp: upstreamResp}
    ca := &CarbolicAcid{Next: next, cfg: cfg}

    rw := &testResponseWriter{}
    rc, err := ca.ServeDNS(context.Background(), rw, makeA("example.com.", "8.8.8.8"))
    if err != nil {
        t.Fatalf("ServeDNS error: %v", err)
    }

    if rc != dns.RcodeSuccess {
        t.Fatalf("drop should still return RcodeSuccess")
    }

    if rw.msg != nil {
        t.Fatalf("drop should NOT write any response")
    }
}

func TestServfail(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {Kind: RuleInclude, Value: "10.0.0.0/8"},
        },
        Action: ActionServfail,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    upstreamResp := makeA("example.com.", "10.1.2.3")
    next := &testNext{resp: upstreamResp}
    ca := &CarbolicAcid{Next: next, cfg: cfg}

    rw := &testResponseWriter{}
    rc, err := ca.ServeDNS(context.Background(), rw, makeA("example.com.", "8.8.8.8"))
    if err != nil {
        t.Fatalf("ServeDNS error: %v", err)
    }

    if rc != dns.RcodeServerFailure {
        t.Fatalf("expected SERVFAIL, got %d", rc)
    }
}

func TestNxdomain(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {Kind: RuleInclude, Value: "10.0.0.0/8"},
        },
        Action: ActionNxdomain,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    upstreamResp := makeA("example.com.", "10.1.2.3")
    next := &testNext{resp: upstreamResp}
    ca := &CarbolicAcid{Next: next, cfg: cfg}

    rw := &testResponseWriter{}
    rc, err := ca.ServeDNS(context.Background(), rw, makeA("example.com.", "8.8.8.8"))
    if err != nil {
        t.Fatalf("ServeDNS error: %v", err)
    }

    if rc != dns.RcodeNameError {
        t.Fatalf("expected NXDOMAIN, got %d", rc)
    }
}

func TestPresetAndBlockMixed(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {Kind: RulePreset, Value: "iana"},
            {Kind: RuleInclude, Value: "5.6.7.0/24"},
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    // 127.0.0.1 属于 preset iana
    resp1 := makeA("example.com.", "127.0.0.1")
    if !cfg.blockList.HasAny(resp1) {
        t.Fatalf("expected 127.0.0.1 to match preset iana")
    }

    // 5.6.7.8 属于 block
    resp2 := makeA("example.com.", "5.6.7.8")
    if !cfg.blockList.HasAny(resp2) {
        t.Fatalf("expected 5.6.7.8 to match block")
    }
}

func TestIPv6Match(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {Kind: RuleInclude, Value: "2001:db8::/32"},
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    resp := new(dns.Msg)
    resp.SetReply(&dns.Msg{
        Question: []dns.Question{
            {Name: "example.com.", Qtype: dns.TypeAAAA},
        },
    })
    rr, _ := dns.NewRR("example.com. 60 IN AAAA 2001:db8::1")
    resp.Answer = append(resp.Answer, rr)

    if !cfg.blockList.HasAny(resp) {
        t.Fatalf("expected IPv6 2001:db8::1 to match blockList")
    }
}

func TestExcludeNotSubsetShouldFail(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {
                Kind:  RuleInclude,
                Value: "1.2.3.0/24",
                Excl:  []string{"1.2.4.0/24"}, // 不是子集
            },
        },
    }

    if err := cfg.initBlockList(); err == nil {
        t.Fatalf("expected initBlockList to fail due to invalid exclude")
    }
}

// 多 Answer：多条 A 记录中只要一条命中就认为整报文命中
func TestMultiAnswerMatch(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {Kind: RuleInclude, Value: "10.0.0.0/8"},
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    m := new(dns.Msg)
    m.SetReply(&dns.Msg{
        Question: []dns.Question{
            {Name: "example.com.", Qtype: dns.TypeA},
        },
    })
    rr1, _ := dns.NewRR("example.com. 60 IN A 1.2.3.4")   // 正常
    rr2, _ := dns.NewRR("example.com. 60 IN A 10.1.2.3")  // 命中 block
    m.Answer = append(m.Answer, rr1, rr2)

    if !cfg.blockList.HasAny(m) {
        t.Fatalf("expected multi-answer response to match blockList when one A is blocked")
    }
}

// 多 RR 类型混合：A + AAAA 中任一命中 blockList 即视为整报文命中
func TestMixedAAndAAAAMatch(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {Kind: RuleInclude, Value: "10.0.0.0/8"},
            {Kind: RuleInclude, Value: "2001:db8::/32"},
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    m := new(dns.Msg)
    m.SetReply(&dns.Msg{
        Question: []dns.Question{
            {Name: "example.com.", Qtype: dns.TypeA},
        },
    })
    aRR, _ := dns.NewRR("example.com. 60 IN A 10.1.2.3")
    aaaaRR, _ := dns.NewRR("example.com. 60 IN AAAA 2001:db8::1")
    m.Answer = append(m.Answer, aRR, aaaaRR)

    if !cfg.blockList.HasAny(m) {
        t.Fatalf("expected mixed A+AAAA response to match blockList")
    }
}

// 多 exclude 合并：来自不同 BlockNode 的 exclude 都应进入 allowList
func TestMultipleExcludesMerged(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {
                Kind:  RuleInclude,
                Value: "1.2.3.0/24",
                Excl:  []string{"1.2.3.4/32"},
            },
            {
                Kind:  RuleInclude,
                Value: "5.6.7.0/24",
                Excl:  []string{"5.6.7.8/32"},
            },
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    resp1 := makeA("example.com.", "1.2.3.4")
    if !cfg.allowList.HasAny(resp1) {
        t.Fatalf("expected 1.2.3.4 to be in allowList")
    }

    resp2 := makeA("example.net.", "5.6.7.8")
    if !cfg.allowList.HasAny(resp2) {
        t.Fatalf("expected 5.6.7.8 to be in allowList")
    }
}

// 多 block 合并：多个 block CIDR 应共同构成 blockList
func TestMultipleBlocksMerged(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {Kind: RuleInclude, Value: "10.0.0.0/8"},
            {Kind: RuleInclude, Value: "192.168.0.0/16"},
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    resp1 := makeA("a.example.", "10.1.2.3")
    if !cfg.blockList.HasAny(resp1) {
        t.Fatalf("expected 10.1.2.3 to match blockList")
    }

    resp2 := makeA("b.example.", "192.168.1.1")
    if !cfg.blockList.HasAny(resp2) {
        t.Fatalf("expected 192.168.1.1 to match blockList")
    }
}

// preset none：允许存在，但不能有 excludes，且不会阻断任何地址
func TestPresetNone(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {Kind: RulePreset, Value: "none"},
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    // 任意地址都不应命中 blockList
    resp := makeA("example.com.", "10.1.2.3")
    if cfg.blockList != nil && cfg.blockList.HasAny(resp) {
        t.Fatalf("preset 'none' should not block any IP")
    }
}

// preset none + exclude -> 应直接报错
func TestPresetNoneWithExcludeShouldFail(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {
                Kind:  RulePreset,
                Value: "none",
                Excl:  []string{"1.2.3.4/32"},
            },
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err == nil {
        t.Fatalf("expected initBlockList to fail when preset 'none' has excludes")
    }
}

// preset allip：0.0.0.0/0 + ::/0，任意 IP 都应命中 blockList
func TestPresetAllIP(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {Kind: RulePreset, Value: "allip"},
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    resp1 := makeA("a.example.", "1.2.3.4")
    if !cfg.blockList.HasAny(resp1) {
        t.Fatalf("expected IPv4 1.2.3.4 to be blocked by allip")
    }

    m := new(dns.Msg)
    m.SetReply(&dns.Msg{
        Question: []dns.Question{
            {Name: "b.example.", Qtype: dns.TypeAAAA},
        },
    })
    aaaa, _ := dns.NewRR("b.example. 60 IN AAAA 2001:db8::1")
    m.Answer = append(m.Answer, aaaa)

    if !cfg.blockList.HasAny(m) {
        t.Fatalf("expected IPv6 2001:db8::1 to be blocked by allip")
    }
}

// allowList 优先：即使同一响应中包含被 block 的 RR，只要有一条在 allowList，就整体放行
func TestAllowListOverridesBlockList(t *testing.T) {
    cfg := &Config{
        Blocks: []*BlockNode{
            {
                Kind:  RuleInclude,
                Value: "1.2.3.0/24",
                Excl:  []string{"1.2.3.4/32"}, // 放行 1.2.3.4
            },
        },
        Action: ActionDrop,
    }

    if err := cfg.initBlockList(); err != nil {
        t.Fatalf("initBlockList failed: %v", err)
    }

    // 上游响应同时包含 1.2.3.4（allow） 和 1.2.3.5（block）
    m := new(dns.Msg)
    m.SetReply(&dns.Msg{
        Question: []dns.Question{
            {Name: "example.com.", Qtype: dns.TypeA},
        },
    })
    rrAllow, _ := dns.NewRR("example.com. 60 IN A 1.2.3.4")
    rrBlock, _ := dns.NewRR("example.com. 60 IN A 1.2.3.5")
    m.Answer = append(m.Answer, rrAllow, rrBlock)

    next := &testNext{resp: m}
    ca := &CarbolicAcid{Next: next, cfg: cfg}

    rw := &testResponseWriter{}
    rc, err := ca.ServeDNS(context.Background(), rw, makeA("example.com.", "8.8.8.8"))
    if err != nil {
        t.Fatalf("ServeDNS error: %v", err)
    }

    if rc != dns.RcodeSuccess {
        t.Fatalf("expected RcodeSuccess, got %d", rc)
    }
    if rw.msg == nil {
        t.Fatalf("expected response to be written due to allowList override")
    }
}

// 基准：大量 block + exclude 下 initBlockList 的性能
func BenchmarkInitBlockList(b *testing.B) {
    // 构造一个较大的配置
    const nBlocks = 256
    blocks := make([]*BlockNode, 0, nBlocks)
    for i := 0; i < nBlocks; i++ {
        cidr := fmt.Sprintf("10.%d.0.0/16", i)
        excl := fmt.Sprintf("10.%d.1.1/32", i)
        blocks = append(blocks, &BlockNode{
            Kind:  RuleInclude,
            Value: cidr,
            Excl:  []string{excl},
        })
    }

    cfg := &Config{
        Blocks: blocks,
        Action: ActionDrop,
    }

    // 先确保不会因为配置错误直接失败
    if err := cfg.initBlockList(); err != nil {
        b.Fatalf("initBlockList sanity check failed: %v", err)
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = cfg.initBlockList()
    }
}
