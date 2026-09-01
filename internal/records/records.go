package records

import (
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

type Record struct {
	Name   string   `yaml:"name" json:"name"`
	Type   string   `yaml:"type" json:"type"`
	TTL    uint32   `yaml:"ttl" json:"ttl"`
	Values []string `yaml:"values" json:"values"`
}

type Store struct {
	// exact map: lower(name) -> qtype -> []RR
	exact map[string]map[uint16][]dns.RR
	// wildcard suffix: e.g. "*.internal.mc" -> suffix "internal.mc"
	wildcards []wildcard
}

type wildcard struct {
	suffix string
	qtype  uint16
	rrs    []dns.RR
}

func New(recs []Record) (*Store, error) {
	s := &Store{
		exact: make(map[string]map[uint16][]dns.RR),
	}
	for _, r := range recs {
		qtype, ok := dns.StringToType[strings.ToUpper(r.Type)]
		if !ok {
			continue
		}
		ttl := r.TTL
		if ttl == 0 {
			ttl = 300
		}
		if strings.HasPrefix(r.Name, "*.") {
			suffix := strings.ToLower(strings.TrimPrefix(r.Name, "*."))
			suffix = dns.Fqdn(suffix)
			var rrs []dns.RR
			for _, v := range r.Values {
				rrStr := dns.Fqdn(r.Name) + " " + strconv.FormatUint(uint64(ttl), 10) + " IN " + r.Type + " " + v
				// For wildcard, use synthesized name later; create template with "*"
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					continue
				}
				rrs = append(rrs, rr)
			}
			s.wildcards = append(s.wildcards, wildcard{suffix: suffix, qtype: qtype, rrs: rrs})
			continue
		}
		fqdn := dns.Fqdn(strings.ToLower(r.Name))
		for _, v := range r.Values {
			rrStr := fqdn + " " + strconv.FormatUint(uint64(ttl), 10) + " IN " + r.Type + " " + v
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				continue
			}
			if s.exact[fqdn] == nil {
				s.exact[fqdn] = make(map[uint16][]dns.RR)
			}
			s.exact[fqdn][qtype] = append(s.exact[fqdn][qtype], rr)
		}
		// Also handle CNAME etc needing exact match on name
	}
	return s, nil
}

// Lookup returns RRs if custom record matches. Second return true if authoritative (we own the name).
func (s *Store) Lookup(q dns.Question) ([]dns.RR, bool) {
	fqdn := dns.Fqdn(strings.ToLower(q.Name))
	// exact
	if m, ok := s.exact[fqdn]; ok {
		if rrs, ok := m[q.Qtype]; ok && len(rrs) > 0 {
			// return copies with correct name? already correct
			out := make([]dns.RR, len(rrs))
			for i, rr := range rrs {
				out[i] = dns.Copy(rr)
			}
			return out, true
		}
		// CNAME handling: if we have CNAME for this name, return it regardless of qtype
		if cnameRRs, ok := m[dns.TypeCNAME]; ok && len(cnameRRs) > 0 && q.Qtype != dns.TypeCNAME {
			out := make([]dns.RR, len(cnameRRs))
			for i, rr := range cnameRRs {
				out[i] = dns.Copy(rr)
			}
			return out, true
		}
		// name exists but type not found -> NODATA (authoritative empty)
		return nil, true
	}
	// wildcard
	for _, w := range s.wildcards {
		if w.qtype != q.Qtype && w.qtype != dns.TypeCNAME {
			continue
		}
		if strings.HasSuffix(fqdn, w.suffix) || fqdn == w.suffix {
			// ensure not exact match already handled and is subdomain
			// produce RRs with q.Name as owner
			var out []dns.RR
			for _, rr := range w.rrs {
				cp := dns.Copy(rr)
				cp.Header().Name = dns.Fqdn(q.Name)
				out = append(out, cp)
			}
			if len(out) > 0 {
				return out, true
			}
		}
	}
	return nil, false
}
