/*
 * @Author: Charley
 * @Date: 2021-08-18 15:37:45
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-20 17:22:52
 * @FilePath: /coredns/plugin/wormhole/defaults.go
 * @Description: 默认定义
 */
package wormhole

import "time"

// 默认配置表，详细定义在clash_config.go
var defaultPluginConfig = WormholeConfig{

	RemoteServers: []string{},

	SubscribeList:     []SubscribeFile{},
	DomainList:        []string{},
	DomainSuffixList:  []string{},
	DomainKeywordList: []string{},
	RegexlistRules:    []string{},

	IgnoreSubscribeList:     []SubscribeFile{},
	IgnoreDomainList:        []string{},
	IgnoreDomainSuffixList:  []string{},
	IgnoreDomainKeywordList: []string{},
	IgnoreRegexlistRules:    []string{},

	Policy: "balancing",

	HttpListRenewalInterval:  time.Hour * 24,
	FileListRenewalInterval:  time.Minute,
	ListRenewalRetryCount:    5,
	ListRenewalRetryInterval: time.Minute,

	EnableAutoUpdate: true,
}
