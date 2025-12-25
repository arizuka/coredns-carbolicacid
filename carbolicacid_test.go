package carbolicacid

import (
    "context"
    "net"
    "testing"

    "github.com/miekg/dns"
)

type fakeWriter struct {
    dns.ResponseWriter
    msg *dns.Msg
}

func (f *fakeWriter) WriteMsg(m *dns.Msg) error {
    f.msg = m
    return nil
}

type fakeNext struct {
    resp *dns.Msg
}

func (f *fakeNext) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    _ = w.WriteMsg(f.resp)
    return dns.RcodeSuccess, nil
}

func (f *fakeNext) Name() string { return "fakeNext" }

// ---------------------- v0.3: drop ----------------------

func TestDropPoisonedARecord(t *testing.T) {
    cfg := &Config{
        Preset:       "none",
        IncludeCIDRs: []string{"0.0.0.0/32"},
        Action:       ActionDrop,
    }
    cfg.initBlockList()

    r := new(dns.Msg)
    r.SetQuestion("example.com.", dns.TypeA)

    resp := new(dns.Msg)
    resp.SetReply(r)
    resp.Answer = []dns.RR{
        &dns.A{
            Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA},
            A:   net.IPv4(0, 0, 0, 0),
        },
    }

    w := &fakeWriter{}
    ca := &CarbolicAcid{
        cfg:  cfg,
        Next: &fakeNext{resp: resp},
    }

    ca.ServeDNS(context.Background(), w, r)

    if w.msg != nil {
        t.Fatalf("drop action should not return any response")
    }
}

// ---------------------- v0.3: servfail ----------------------

func TestServfailPoisonedARecord(t *testing.T) {
    cfg := &Config{
        Preset:       "none",
        IncludeCIDRs: []string{"0.0.0.0/32"},
        Action:       ActionServfail,
    }
    cfg.initBlockList()

    r := new(dns.Msg)
    r.SetQuestion("example.com.", dns.TypeA)

    resp := new(dns.Msg)
    resp.SetReply(r)
    resp.Answer = []dns.RR{
        &dns.A{
            Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA},
            A:   net.IPv4(0, 0, 0, 0),
        },
    }

    w := &fakeWriter{}
    ca := &CarbolicAcid{
        cfg:  cfg,
        Next: &fakeNext{resp: resp},
    }

    ca.ServeDNS(context.Background(), w, r)

    if w.msg == nil || w.msg.Rcode != dns.RcodeServerFailure {
        t.Fatalf("servfail action should return SERVFAIL")
    }
}

// ---------------------- v0.3: nxdomain ----------------------

func TestNxdomainPoisonedARecord(t *testing.T) {
    cfg := &Config{
        Preset:       "none",
        IncludeCIDRs: []string{"0.0.0.0/32"},
        Action:       ActionNxdomain,
    }
    cfg.initBlockList()

    r := new(dns.Msg)
    r.SetQuestion("example.com.", dns.TypeA)

    resp := new(dns.Msg)
    resp.SetReply(r)
    resp.Answer = []dns.RR{
        &dns.A{
            Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA},
            A:   net.IPv4(0, 0, 0, 0),
        },
    }

    w := &fakeWriter{}
    ca := &CarbolicAcid{
        cfg:  cfg,
        Next: &fakeNext{resp: resp},
    }

    ca.ServeDNS(context.Background(), w, r)

    if w.msg == nil || w.msg.Rcode != dns.RcodeNameError {
        t.Fatalf("nxdomain action should return NXDOMAIN")
    }
}

// ---------------------- v0.3: pass-through tests ----------------------

func TestDefaultNoAction(t *testing.T) {
    cfg := &Config{
        Preset: "none",
        Action: ActionDrop,
    }
    cfg.initBlockList()

    r := new(dns.Msg)
    r.SetQuestion("example.com.", dns.TypeA)

    resp := new(dns.Msg)
    resp.SetReply(r)
    resp.Answer = []dns.RR{
        &dns.A{
            Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA},
            A:   net.IPv4(1, 1, 1, 1),
        },
    }

    w := &fakeWriter{}
    ca := &CarbolicAcid{
        cfg:  cfg,
        Next: &fakeNext{resp: resp},
    }

    ca.ServeDNS(context.Background(), w, r)

    if w.msg == nil {
        t.Fatalf("normal response should not be blocked")
    }
}

func TestCNAMEOnlyNoAction(t *testing.T) {
    cfg := &Config{
        Preset: "none",
        Action: ActionDrop,
    }
    cfg.initBlockList()

    r := new(dns.Msg)
    r.SetQuestion("example.com.", dns.TypeCNAME)

    resp := new(dns.Msg)
    resp.SetReply(r)
    resp.Answer = []dns.RR{
        &dns.CNAME{
            Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCNAME},
            Target: "real.example.com.",
        },
    }

    w := &fakeWriter{}
    ca := &CarbolicAcid{
        cfg:  cfg,
        Next: &fakeNext{resp: resp},
    }

    ca.ServeDNS(context.Background(), w, r)

    if w.msg == nil {
        t.Fatalf("CNAME-only response should not be blocked")
    }
}

func TestTXTOnlyNoAction(t *testing.T) {
    cfg := &Config{
        Preset: "none",
        Action: ActionDrop,
    }
    cfg.initBlockList()

    r := new(dns.Msg)
    r.SetQuestion("example.com.", dns.TypeTXT)

    resp := new(dns.Msg)
    resp.SetReply(r)
    resp.Answer = []dns.RR{
        &dns.TXT{
            Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT},
            Txt: []string{"hello world"},
        },
    }

    w := &fakeWriter{}
    ca := &CarbolicAcid{
        cfg:  cfg,
        Next: &fakeNext{resp: resp},
    }

    ca.ServeDNS(context.Background(), w, r)

    if w.msg == nil {
        t.Fatalf("TXT-only response should not be blocked")
    }
}
