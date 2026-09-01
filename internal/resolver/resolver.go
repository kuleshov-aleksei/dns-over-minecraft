package resolver

import (
	"context"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/cache"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/records"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/upstream"
	"github.com/miekg/dns"
)

type Resolver struct {
	cache   *cache.Cache
	records *records.Store
	pool    *upstream.Pool
}

func New(c *cache.Cache, s *records.Store, p *upstream.Pool) *Resolver {
	return &Resolver{cache: c, records: s, pool: p}
}

func (r *Resolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if len(q.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Rcode = dns.RcodeFormatError
		return resp, nil
	}
	question := q.Question[0]

	// 1. cache
	if r.cache != nil {
		if cached, ok := r.cache.Get(question); ok {
			cached.Id = q.Id
			cached.Question = q.Question
			return cached, nil
		}
	}

	// 2. custom records (authoritative)
	if r.records != nil {
		if rrs, authoritative := r.records.Lookup(question); authoritative {
			resp := new(dns.Msg)
			resp.SetReply(q)
			resp.Authoritative = true
			resp.RecursionAvailable = true
			if len(rrs) > 0 {
				resp.Answer = rrs
			} else {
				// NODATA? For MVP return NOERROR empty or NXDOMAIN if name not found?
				// If wildcard/exact matched but no type, we signal NODATA (NOERROR empty)
				// If Store said authoritative but no RRs, return NOERROR empty
				// To allow NXDOMAIN for custom block, user can create no records and we treat as NXDOMAIN?
				// For now NOERROR empty (NODATA)
			}
			if r.cache != nil {
				r.cache.Set(question, resp)
			}
			return resp, nil
		}
	}

	// 3. upstream pool
	if r.pool == nil || len(r.pool.List()) == 0 {
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Rcode = dns.RcodeServerFailure
		return resp, nil
	}
	resp, err := r.pool.Exchange(ctx, q)
	if err != nil {
		fail := new(dns.Msg)
		fail.SetReply(q)
		fail.Rcode = dns.RcodeServerFailure
		return fail, nil
	}
	if r.cache != nil {
		r.cache.Set(question, resp)
	}
	return resp, nil
}
