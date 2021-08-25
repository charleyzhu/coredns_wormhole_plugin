/*
 * @Author: Charley
 * @Date: 2021-08-13 11:48:18
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-25 08:32:34
 * @FilePath: /coredns/plugin/wormhole/setup.go
 * @Description: 配置读取配置文件初始化插件
 */
package wormhole

import (
	"fmt"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/parse"
)

const pluginName = "wormhole"

var log = clog.NewWithPlugin(pluginName)

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	w, err := parseWormhole(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		w.Next = next
		return w
	})

	c.OnStartup(func() error {
		return w.OnStartup()
	})

	c.OnShutdown(func() error {
		return w.OnShutdown()
	})

	return nil
}

func parseWormhole(c *caddy.Controller) (*Wormhole, error) {
	var (
		cl *Wormhole
		i  int
	)

	for c.Next() {
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++
		cfg, err := parsePluginConfiguration(c)
		if err != nil {
			return nil, err
		}
		cl, err = parseConfig(cfg)
		if err != nil {
			return nil, err
		}
	}
	return cl, nil
}

func parseConfig(cfg *WormholeConfig) (*Wormhole, error) {
	w := NewWormhole()
	// 解析转发服务器
	proxies, err := parseRemoteServer(cfg.RemoteServers)
	if err != nil {
		return nil, err
	}
	w.proxies = proxies

	// 先解析配置文件中定义好的域名，后期插件启动的时候再更新订阅
	staticRuleList, staticIgnoreRuleList := parseStaticRule(cfg)

	w.StaticRuleList = append(w.StaticRuleList, staticRuleList...)
	w.StaticIgnoreRuleList = append(w.StaticIgnoreRuleList, staticIgnoreRuleList...)

	ruleList, ignoreRuleList := parseSubscribeRuleGroup(cfg)
	w.RuleList = append(w.RuleList, ruleList...)
	w.IgnoreRuleList = append(w.IgnoreRuleList, ignoreRuleList...)

	w.policy = parsePolicy(cfg)

	if cfg.ROSConfig != nil {
		w.ros = NewRouterOS(cfg.ROSConfig)
	}

	w.config = cfg

	return w, nil
}

func parseRemoteServer(hosts []string) ([]*Proxy, error) {

	var proxies []*Proxy

	toHosts, err := parse.HostPortOrFile(hosts...)
	if err != nil {
		return nil, err
	}
	allowedTrans := map[string]bool{"dns": true, "tls": true}

	for _, host := range toHosts {
		trans, addr := parse.Transport(host)

		if !allowedTrans[trans] {
			return nil, fmt.Errorf("'%s' is not supported as a destination protocol in forward: %s", trans, host)
		}

		log.Infof("trans=%s address=%s", trans, addr)

		proxy := NewProxy(trans, addr)
		proxies = append(proxies, proxy)

	}
	return proxies, nil
}

func parseStaticRule(cfg *WormholeConfig) ([]Rule, []Rule) {
	var (
		ruleList       []Rule
		ignoreRuleList []Rule
	)

	for _, domian := range cfg.DomainList {
		rule := NewRuleDomain(domian)
		ruleList = append(ruleList, rule)
	}

	for _, domian := range cfg.DomainSuffixList {
		rule := NewRuleDomainSuffix(domian)
		ruleList = append(ruleList, rule)
	}

	for _, keyword := range cfg.DomainKeywordList {
		rule := NewRuleDomainKeyword(keyword)
		ruleList = append(ruleList, rule)
	}

	for _, regex := range cfg.RegexlistRules {
		rule := NewRuleRegex(regex)
		ruleList = append(ruleList, rule)
	}

	for _, domian := range cfg.IgnoreDomainList {
		rule := NewRuleDomain(domian)
		ignoreRuleList = append(ignoreRuleList, rule)
	}

	for _, domian := range cfg.IgnoreDomainSuffixList {
		rule := NewRuleDomainSuffix(domian)
		ignoreRuleList = append(ignoreRuleList, rule)
	}

	for _, domian := range cfg.IgnoreDomainKeywordList {
		rule := NewRuleDomainKeyword(domian)
		ignoreRuleList = append(ignoreRuleList, rule)
	}

	for _, regex := range cfg.IgnoreRegexlistRules {
		rule := NewRuleRegex(regex)
		ignoreRuleList = append(ignoreRuleList, rule)
	}

	return ruleList, ignoreRuleList
}

func parseSubscribeRuleGroup(cfg *WormholeConfig) ([]SubscribeRuleGroup, []SubscribeRuleGroup) {
	var (
		ruleList       []SubscribeRuleGroup
		ignoreRuleList []SubscribeRuleGroup
	)

	for _, subscribeFile := range cfg.SubscribeList {
		ruleGroup := NewSubscribeRuleGroup(subscribeFile, []Rule{}, cfg.ListRenewalRetryCount, cfg.ListRenewalRetryInterval)
		ruleList = append(ruleList, ruleGroup)
	}

	for _, subscribeFile := range cfg.IgnoreSubscribeList {
		ruleGroup := NewSubscribeRuleGroup(subscribeFile, []Rule{}, cfg.ListRenewalRetryCount, cfg.ListRenewalRetryInterval)
		ignoreRuleList = append(ignoreRuleList, ruleGroup)
	}
	return ruleList, ignoreRuleList
}

func parsePolicy(cfg *WormholeConfig) Policy {
	var policy Policy
	switch x := cfg.Policy; x {
	case "balancing":
		policy = PolicyBalancing
	case "parallel":
		policy = PolicyParallel
	case "fastTest":
		policy = PolicyFastTest
	default:
		policy = PolicyBalancing
	}
	return policy
}

// OnStartup starts a goroutines for all proxies.
func (c *Wormhole) OnStartup() (err error) {
	c.start()
	return nil
}

// OnShutdown stops all configured proxies.
func (c *Wormhole) OnShutdown() error {
	return nil
}
