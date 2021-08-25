/*
 * @Author: Charley
 * @Date: 2021-08-25 08:55:33
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-25 10:37:46
 * @FilePath: /coredns/plugin/wormhole/rule_ip_cidr.go
 * @Description: In User Settings Edit
 */

package wormhole

import (
	"github.com/miekg/dns"
)

type RuleIPCIDR struct {
	target string
}

func (rd RuleIPCIDR) RuleType() RuleType {
	return RuleTypeIPCIDR
}

func (rd RuleIPCIDR) Match(msg *dns.Msg) bool {
	return false
}

func (rd RuleIPCIDR) Payload() string {
	return rd.target
}

func NewRuleIPCIDR(target string) RuleIPCIDR {
	return RuleIPCIDR{
		target: target,
	}
}
