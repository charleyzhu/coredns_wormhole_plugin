/*
 * @Author: Charley
 * @Date: 2021-08-17 08:57:54
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-25 10:05:25
 * @FilePath: /coredns/plugin/wormhole/rule_type.go
 * @Description: 匹配规则类型
 */
package wormhole

const (
	RuleTypeDomain RuleType = iota
	RuleTypeDomainSuffix
	RuleTypeDomainKeyword
	RuleTypeRegex
	RuleTypeSubscribeGroup
	RuleTypeStaticGroup
	RuleTypeIPCIDR
	RuleTypeUnknown
)

type RuleType int

func (r RuleType) String() string {
	switch r {
	case RuleTypeDomain:
		return "Domain"
	case RuleTypeDomainSuffix:
		return "DomainSuffix"
	case RuleTypeDomainKeyword:
		return "DomainKeyword"
	case RuleTypeRegex:
		return "Regex"
	case RuleTypeSubscribeGroup:
		return "SubscribeGroup"
	case RuleTypeStaticGroup:
		return "StaticGroup"
	case RuleTypeIPCIDR:
		return "RuleTypeIP-CIDR"
	default:
		return "Unknown"
	}
}
