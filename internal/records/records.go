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
	exact     map[string]map[uint16][]dns.RR
	wildcards []wildcard
}

type wildcard struct {
	suffix        string
	queryType     uint16
	resourceRecords []dns.RR
}

func New(inputRecords []Record) (*Store, error) {
	recordStore := &Store{
		exact: make(map[string]map[uint16][]dns.RR),
	}
	for _, record := range inputRecords {
		queryType, exists := dns.StringToType[strings.ToUpper(record.Type)]
		if !exists {
			continue
		}
		timeToLive := record.TTL
		if timeToLive == 0 {
			timeToLive = 300
		}
		if strings.HasPrefix(record.Name, "*.") {
			suffix := strings.ToLower(strings.TrimPrefix(record.Name, "*."))
			suffix = dns.Fqdn(suffix)
			var wildcardRecords []dns.RR
			for _, value := range record.Values {
				recordString := dns.Fqdn(record.Name) + " " + strconv.FormatUint(uint64(timeToLive), 10) + " IN " + record.Type + " " + value
				resourceRecord, err := dns.NewRR(recordString)
				if err != nil {
					continue
				}
				wildcardRecords = append(wildcardRecords, resourceRecord)
			}
			recordStore.wildcards = append(recordStore.wildcards, wildcard{suffix: suffix, queryType: queryType, resourceRecords: wildcardRecords})
			continue
		}
		fullyQualifiedName := dns.Fqdn(strings.ToLower(record.Name))
		for _, value := range record.Values {
			recordString := fullyQualifiedName + " " + strconv.FormatUint(uint64(timeToLive), 10) + " IN " + record.Type + " " + value
			resourceRecord, err := dns.NewRR(recordString)
			if err != nil {
				continue
			}
			if recordStore.exact[fullyQualifiedName] == nil {
				recordStore.exact[fullyQualifiedName] = make(map[uint16][]dns.RR)
			}
			recordStore.exact[fullyQualifiedName][queryType] = append(recordStore.exact[fullyQualifiedName][queryType], resourceRecord)
		}
	}
	return recordStore, nil
}

// Lookup returns RRs if custom record matches. Second return true if authoritative (we own the name).
func (recordStore *Store) Lookup(question dns.Question) ([]dns.RR, bool) {
	fullyQualifiedName := dns.Fqdn(strings.ToLower(question.Name))
	if typeMap, exists := recordStore.exact[fullyQualifiedName]; exists {
		if matchedRecords, exists := typeMap[question.Qtype]; exists && len(matchedRecords) > 0 {
			resultRecords := make([]dns.RR, len(matchedRecords))
			for index, resourceRecord := range matchedRecords {
				resultRecords[index] = dns.Copy(resourceRecord)
			}
			return resultRecords, true
		}
		if cnameRecords, exists := typeMap[dns.TypeCNAME]; exists && len(cnameRecords) > 0 && question.Qtype != dns.TypeCNAME {
			resultRecords := make([]dns.RR, len(cnameRecords))
			for index, resourceRecord := range cnameRecords {
				resultRecords[index] = dns.Copy(resourceRecord)
			}
			return resultRecords, true
		}
		return nil, true
	}
	for _, wildcardEntry := range recordStore.wildcards {
		if wildcardEntry.queryType != question.Qtype && wildcardEntry.queryType != dns.TypeCNAME {
			continue
		}
		if strings.HasSuffix(fullyQualifiedName, wildcardEntry.suffix) || fullyQualifiedName == wildcardEntry.suffix {
			var resultRecords []dns.RR
			for _, resourceRecord := range wildcardEntry.resourceRecords {
				copiedRecord := dns.Copy(resourceRecord)
				copiedRecord.Header().Name = dns.Fqdn(question.Name)
				resultRecords = append(resultRecords, copiedRecord)
			}
			if len(resultRecords) > 0 {
				return resultRecords, true
			}
		}
	}
	return nil, false
}
