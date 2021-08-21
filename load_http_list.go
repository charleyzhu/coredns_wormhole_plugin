/*
 * @Author: Charley
 * @Date: 2021-08-18 17:45:45
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-20 14:18:57
 * @FilePath: /coredns/plugin/wormhole/load_http_list.go
 * @Description: 加载订阅文件
 */
package wormhole

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

func (w *Wormhole) getFilterSubscribeList() ([]*SubscribeRuleGroup, []*SubscribeRuleGroup, []*SubscribeRuleGroup, []*SubscribeRuleGroup) {
	httpSubscribe, fileSubscribe := w.filterSubscribeList()
	httpIgnoreSubscribe, fileIgnoreSubscribe := w.filterIgnoreSubscribeList()
	return httpSubscribe, fileSubscribe, httpIgnoreSubscribe, fileIgnoreSubscribe
}

func (w *Wormhole) getFilterHttpSubscribeList() ([]*SubscribeRuleGroup, []*SubscribeRuleGroup) {
	httpSubscribe, _ := w.filterSubscribeList()
	httpIgnoreSubscribe, _ := w.filterIgnoreSubscribeList()
	return httpSubscribe, httpIgnoreSubscribe
}

func (w *Wormhole) getFilterFileSubscribeList() ([]*SubscribeRuleGroup, []*SubscribeRuleGroup) {
	_, fileSubscribe := w.filterSubscribeList()
	_, fileIgnoreSubscribe := w.filterIgnoreSubscribeList()
	return fileSubscribe, fileIgnoreSubscribe
}

func (w *Wormhole) filterSubscribeList() ([]*SubscribeRuleGroup, []*SubscribeRuleGroup) {
	var httpSubscribe []*SubscribeRuleGroup
	var fileSubscribe []*SubscribeRuleGroup
	for i := range w.RuleList {

		if w.RuleList[i].subscribe.isOnlineSubscribe {
			httpSubscribe = append(httpSubscribe, &w.RuleList[i])
		} else {
			fileSubscribe = append(fileSubscribe, &w.RuleList[i])
		}
	}

	return httpSubscribe, fileSubscribe
}

func (w *Wormhole) filterIgnoreSubscribeList() ([]*SubscribeRuleGroup, []*SubscribeRuleGroup) {
	var httpSubscribe []*SubscribeRuleGroup
	var fileSubscribe []*SubscribeRuleGroup
	for i := range w.IgnoreRuleList {

		if w.RuleList[i].subscribe.isOnlineSubscribe {
			httpSubscribe = append(httpSubscribe, &w.RuleList[i])
		} else {
			fileSubscribe = append(fileSubscribe, &w.RuleList[i])
		}
	}

	return httpSubscribe, fileSubscribe
}

func updateHttpSubscribeList(subscribeGroupList []*SubscribeRuleGroup) {

	for i := range subscribeGroupList {
		subscribeRuleGroup := subscribeGroupList[i]
		subscribeRuleGroup.UpdateRule()
	}
}

func updateFileSubscribeGroup(subscribeGroupList []*SubscribeRuleGroup) {

	for i := range subscribeGroupList {
		subscribeRuleGroup := subscribeGroupList[i]
		file, err := os.Open(subscribeRuleGroup.subscribe.Url)
		if err != nil {
			log.Warningf("open subscribe file find error:%s", err.Error())
			continue
		}
		fileInfo, err := file.Stat()
		if err != nil {
			log.Warningf("Stat file find error:%s", err.Error())
			continue
		}
		curModifyTime := fileInfo.ModTime().Unix()
		lastUpdateTime := subscribeRuleGroup.LastUpdateTime()
		if curModifyTime > lastUpdateTime {
			log.Infof("Find subscribe change load form %s", subscribeRuleGroup.subscribe.Url)
			subscribeRuleGroup.UpdateRule()
		}

	}
}

func loadDomainListFormUrl(url string) ([]byte, error) {
	log.Infof("Load Subscribe Form Ulr:%s", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func loadDomainListFormFile(url string) ([]byte, error) {
	// if !filepath.IsAbs(url) {
	// 	url = filepath.Join(
	// 		filepath.Dir(c.File()),
	// 		url,
	// 	)
	// }

	log.Infof("Load Subscribe Form file:%s", url)

	content, err := ioutil.ReadFile(url)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func parseClashRules(yamlContent []byte) ([]Rule, error) {
	clashRuleFile := &ClashRuleFile{}
	err := yaml.Unmarshal(yamlContent, clashRuleFile)
	if err != nil {
		return nil, err
	}
	var ruleList []Rule
	for _, ruleLine := range clashRuleFile.Payload {

		rule, err := parseClashRulesLine(ruleLine)
		if err != nil {
			return nil, err
		}
		if rule == nil {
			continue
		}

		ruleList = append(ruleList, rule)
	}
	return ruleList, nil
}

func parseClashRulesLine(ruleLine string) (Rule, error) {
	lineArray := strings.Split(ruleLine, ",")
	if len(lineArray) < 2 {
		return nil, fmt.Errorf("ParseRule: %s error", ruleLine)
	}

	ruleType := lineArray[0]
	payload := lineArray[1]

	var rule Rule

	switch ruleType {
	case "DOMAIN-SUFFIX":
		rule = NewRuleDomainSuffix(payload)

	case "DOMAIN-KEYWORD":
		rule = NewRuleDomainKeyword(payload)

	case "DOMAIN":
		rule = NewRuleDomain(payload)

	}
	return rule, nil
}

func parseDnsmasqRules(fileContent []byte) ([]Rule, error) {
	content := string(fileContent)
	contentArray := strings.Split(content, "\n")

	var ruleList []Rule
	for _, ruleLine := range contentArray {

		rule, err := parseDnsmasqRulesLine(ruleLine)
		if err != nil {
			log.Warningf("Parse Dnsmasq Rules Find Error:%s", err.Error())
			continue
		}
		if rule == nil {
			continue
		}

		ruleList = append(ruleList, rule)
	}
	return ruleList, nil
}

func parseDnsmasqRulesLine(ruleLine string) (Rule, error) {
	lineArray := strings.Split(ruleLine, "=")
	if len(lineArray) != 2 {
		return nil, fmt.Errorf("ParseRule lineArray: %s error", ruleLine)
	}
	domainLine := lineArray[1]
	domainArray := strings.Split(domainLine, "/")
	if len(domainArray) != 3 {
		return nil, fmt.Errorf("ParseRule domainArray : %s error", ruleLine)
	}

	return NewRuleDomainSuffix(domainArray[1]), nil
}
