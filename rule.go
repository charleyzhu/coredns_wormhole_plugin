/*
 * @Author: Charley
 * @Date: 2021-08-17 10:43:03
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-20 09:15:08
 * @FilePath: /coredns/plugin/wormhole/rule.go
 * @Description: 匹配规则定义
 */
package wormhole

import (
	"regexp"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type Rule interface {
	RuleType() RuleType
	Match(msg *dns.Msg) bool
	Payload() string
}

// RuleDomain
type RuleDomain struct {
	domain string
}

func (rd RuleDomain) RuleType() RuleType {
	return RuleTypeDomain
}

func (rd RuleDomain) Match(msg *dns.Msg) bool {
	if len(msg.Question) <= 0 {
		return false
	}
	domain := msg.Question[0].Name
	return rd.domain == domain
}

func (rd RuleDomain) Payload() string {
	return rd.domain
}

func NewRuleDomain(domain string) RuleDomain {
	if strings.HasSuffix(domain, ".") {
		return RuleDomain{domain: domain}
	} else {
		return RuleDomain{domain: domain + "."}
	}
}

// RuleSuffix
type RuleDomainSuffix struct {
	domain string
}

func (rds RuleDomainSuffix) RuleType() RuleType {
	return RuleTypeDomainSuffix
}

func (rds RuleDomainSuffix) Match(msg *dns.Msg) bool {
	if len(msg.Question) <= 0 {
		return false
	}
	domain := msg.Question[0].Name
	if rds.domain == domain {
		return true
	}
	if plugin.Name(rds.domain).Matches(domain) {
		return true
	}
	return false
}

func (rds RuleDomainSuffix) Payload() string {
	return rds.domain
}

func NewRuleDomainSuffix(domain string) RuleDomainSuffix {
	if strings.HasSuffix(domain, ".") {
		return RuleDomainSuffix{domain: domain}
	} else {
		return RuleDomainSuffix{domain: domain + "."}
	}

}

// RuleDomainKeyword
type RuleDomainKeyword struct {
	keyword string
}

func (rdk RuleDomainKeyword) RuleType() RuleType {
	return RuleTypeDomainKeyword
}

func (rdk RuleDomainKeyword) Match(msg *dns.Msg) bool {
	if len(msg.Question) <= 0 {
		return false
	}
	domain := msg.Question[0].Name

	return strings.Contains(domain, rdk.keyword)
}

func (rdk RuleDomainKeyword) Payload() string {
	return rdk.keyword
}

func NewRuleDomainKeyword(keyword string) RuleDomainKeyword {
	return RuleDomainKeyword{keyword: keyword}
}

// RuleRegex
type RuleRegex struct {
	regex string
}

func (rr RuleRegex) RuleType() RuleType {
	return RuleTypeRegex
}

func (rr RuleRegex) Match(msg *dns.Msg) bool {

	if len(msg.Question) <= 0 {
		return false
	}
	domain := msg.Question[0].Name
	matched, _ := regexp.MatchString(rr.regex, domain)
	return matched
}

func (rr RuleRegex) Payload() string {
	return rr.regex
}

func NewRuleRegex(regex string) RuleRegex {
	return RuleRegex{regex: regex}
}
