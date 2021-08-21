/*
 * @Author: Charley
 * @Date: 2021-08-20 09:14:33
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-20 14:48:10
 * @FilePath: /coredns/plugin/wormhole/rule_group.go
 * @Description: 规则组
 */
package wormhole

import (
	"time"

	"github.com/miekg/dns"
)

type SubscribeRuleGroup struct {
	subscribe SubscribeFile
	ruleGroup []Rule

	lastUpdateTime time.Time

	listRenewalRetryCount    int           //遇到错误以后重试的次数
	listRenewalRetryInterval time.Duration //遇到错误以后重试的间隔时间
}

func (srg SubscribeRuleGroup) RuleType() RuleType {
	return RuleTypeSubscribeGroup
}

func (srg SubscribeRuleGroup) Match(msg *dns.Msg) bool {
	if len(msg.Question) <= 0 {
		return false
	}

	for _, rule := range srg.ruleGroup {
		if rule.Match(msg) {
			return true
		}
	}

	return false
}

func (srg SubscribeRuleGroup) Payload() string {
	return srg.subscribe.Url
}

func (srg *SubscribeRuleGroup) UpdateRule() error {
	if srg.subscribe.isOnlineSubscribe {
		failCount := 0
		for failCount < srg.listRenewalRetryCount {
			err := srg.updateHandelWithFormUrl()
			if err != nil {
				log.Errorf("Attempt %d/%d failed. Error %q", failCount+1, srg.listRenewalRetryCount, err.Error())
				failCount++
				time.Sleep(srg.listRenewalRetryInterval)
				continue
			}
			log.Infof("Lists with HTTP URL:%s have been updated", srg.subscribe.Url)
			break
		}

	} else {
		srg.updateHandelWithFormFile()
	}

	return nil
}

func (srg *SubscribeRuleGroup) updateHandelWithFormUrl() error {
	content, err := loadDomainListFormUrl(srg.subscribe.Url)
	if err != nil {
		log.Errorf("Load Http Subscribe %s find error %s", srg.subscribe.Url, err)
		return err
	}
	if srg.subscribe.FileType == SubscribeFileTypeClash {
		rList, err := parseClashRules(content)
		if err != nil {
			log.Warningf("Load Http Subscribe %s parse Clash Rules error %s", srg.subscribe.Url, err)
			return err
		}
		srg.lastUpdateTime = time.Now()
		srg.ruleGroup = rList

	} else if srg.subscribe.FileType == SubscribeFileTypeDnsmasq {
		rList, err := parseDnsmasqRules(content)
		if err != nil {
			log.Warningf("Load File Subscribe %s parse Dnsmasq Rules error %s", srg.subscribe.Url, err)
			return err
		}
		srg.lastUpdateTime = time.Now()
		srg.ruleGroup = rList
	}
	return nil
}

func (srg *SubscribeRuleGroup) updateHandelWithFormFile() error {
	content, err := loadDomainListFormFile(srg.subscribe.Url)
	if err != nil {
		log.Warningf("Load File Subscribe %s find error %s", srg.subscribe.Url, err)
		return err
	}

	if srg.subscribe.FileType == SubscribeFileTypeClash {
		rList, err := parseClashRules(content)
		if err != nil {
			log.Warningf("load Subscribe %s parse Clash Rules error %s", srg.subscribe.Url, err)
			return err
		}
		srg.lastUpdateTime = time.Now()
		srg.ruleGroup = rList
	} else if srg.subscribe.FileType == SubscribeFileTypeDnsmasq {
		rList, err := parseDnsmasqRules(content)
		if err != nil {
			log.Warningf("load Subscribe %s parse Dnsmasq Rules error %s", srg.subscribe.Url, err)
			return err
		}
		srg.lastUpdateTime = time.Now()
		srg.ruleGroup = rList
	}
	return nil
}

func (srg *SubscribeRuleGroup) LastUpdateTime() int64 {
	return srg.lastUpdateTime.Unix()
}

func NewSubscribeRuleGroup(subscribe SubscribeFile, ruleGroup []Rule, listRenewalRetryCount int, listRenewalRetryInterval time.Duration) SubscribeRuleGroup {
	return SubscribeRuleGroup{
		subscribe:                subscribe,
		ruleGroup:                ruleGroup,
		listRenewalRetryCount:    listRenewalRetryCount,
		listRenewalRetryInterval: listRenewalRetryInterval,
	}
}

type StaticRuleGroup struct {
	ruleGroup []Rule
}

func (srg StaticRuleGroup) RuleType() RuleType {
	return RuleTypeStaticGroup
}

func (srg StaticRuleGroup) Match(msg *dns.Msg) bool {
	if len(msg.Question) <= 0 {
		return false
	}

	for _, rule := range srg.ruleGroup {
		if rule.Match(msg) {
			return true
		}
	}

	return false
}

func (srg StaticRuleGroup) Payload() string {
	return "srg.ruleGroup"
}

func NewStaticRuleGroup(ruleGroup []Rule) StaticRuleGroup {
	return StaticRuleGroup{

		ruleGroup: ruleGroup,
	}
}
