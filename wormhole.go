/*
 * @Author: Charley
 * @Date: 2021-08-13 11:53:13
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-25 10:59:28
 * @FilePath: /coredns/plugin/wormhole/wormhole.go
 * @Description: 插件主题结构
 */
package wormhole

import (
	"context"
	"fmt"
	"math"
	"strconv"

	"sort"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/go-ping/ping"

	"github.com/miekg/dns"
)

func NewWormhole() *Wormhole {
	c := &Wormhole{}
	return c
}

type Wormhole struct {
	proxies []*Proxy
	policy  Policy

	StaticRuleList       []Rule
	StaticIgnoreRuleList []Rule

	RuleList       []SubscribeRuleGroup
	IgnoreRuleList []SubscribeRuleGroup

	httpUpdateTicker *time.Ticker
	fileUpdateTicker *time.Ticker

	config *WormholeConfig
	ros    *RouterOS

	Next plugin.Handler
}

// Name implements the Handler interface.
func (wh *Wormhole) Name() string {
	return pluginName
}

func (wh *Wormhole) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	for _, rule := range wh.StaticIgnoreRuleList {
		if rule.Match(r) {
			log.Debugf("match static Ignore rule type:%s payload:%s", rule.RuleType(), rule.Payload())
			return plugin.NextOrFailure(pluginName, wh.Next, ctx, w, r)
		}
	}

	for _, rule := range wh.IgnoreRuleList {
		if rule.Match(r) {
			log.Debugf("match Ignore rule type:%s payload:%s", rule.RuleType(), rule.Payload())
			return plugin.NextOrFailure(pluginName, wh.Next, ctx, w, r)
		}
	}

	for _, rule := range wh.StaticRuleList {
		if rule.Match(r) {
			log.Debugf("match static rule type:%s payload:%s", rule.RuleType(), rule.Payload())
			return wh.QueryAndWriteMsg(ctx, w, r)
		}
	}

	for _, rule := range wh.RuleList {
		if rule.Match(r) {
			log.Debugf("match rule type:%s payload:%s", rule.RuleType(), rule.Payload())
			return wh.QueryAndWriteMsg(ctx, w, r)
		}
	}
	return plugin.NextOrFailure(pluginName, wh.Next, ctx, w, r)
}

func (wh *Wormhole) QueryAndWriteMsg(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	var (
		msg *dns.Msg

		err error
	)
	switch wh.policy {
	case PolicyBalancing:
		msg, _, err = wh.BalancingQuery(r)
	case PolicyParallel:
		msg, _, err = wh.ParallelQuery(r)
	case PolicyFastTest:
		msg, _, err = wh.FastTestQuery(r)
	default:
		msg, _, err = wh.BalancingQuery(r)
	}

	if err != nil {
		log.Warningf("Query form remote server find error:%s", err)
		return plugin.NextOrFailure(pluginName, wh.Next, ctx, w, r)
	}

	if wh.ros != nil {
		err := wh.ros.AddDnsMsgAddress(msg)
		if err != nil {
			log.Errorf("%s", err)
		}
	}

	w.WriteMsg(msg)
	return 0, nil
}

func (wh *Wormhole) BalancingQuery(r *dns.Msg) (*dns.Msg, time.Duration, error) {

	for _, proxy := range wh.proxies {
		r, rtt, err := proxy.Query(r)
		if err == nil {
			return r, rtt, err
		}
	}
	return nil, 0, fmt.Errorf("all servers failed to resolve")
}

func (wh *Wormhole) ParallelQuery(r *dns.Msg) (*dns.Msg, time.Duration, error) {

	qmChan := make(chan QueryModel)

	for _, rProxy := range wh.proxies {
		go func(proxy *Proxy) {
			r, rtt, err := proxy.Query(r)
			rqm := NewQueryModel(r, rtt, err)
			qmChan <- rqm

		}(rProxy)
	}

	var queryModel *QueryModel
	for i := 0; i <= len(wh.proxies); i++ {
		qm := <-qmChan
		if qm.err == nil {
			queryModel = &qm
			break
		}
	}

	if queryModel == nil {
		return nil, 0, fmt.Errorf("all servers failed to resolve")
	} else {
		return queryModel.msg, queryModel.rtt, queryModel.err
	}

}

func (wh *Wormhole) FastTestQuery(r *dns.Msg) (*dns.Msg, time.Duration, error) {
	var wg sync.WaitGroup //定义一个同步等待的组

	proxies := wh.proxies
	wg.Add(len(proxies))
	qmChan := make(chan AvgRttQueryModel, len(proxies))
	for _, rProxy := range proxies {

		go func(proxy *Proxy, qc chan AvgRttQueryModel) {
			r, rtt, err := proxy.Query(r)
			if err != nil {
				wg.Done()
				return
			}
			if len(r.Answer) <= 0 {
				wg.Done()
				return
			}
			addr := r.Answer[0].String()
			avgRtt := wh.TestPing(addr)
			rqm := NewAvgRttQueryModel(r, rtt, avgRtt, err)
			qc <- rqm
			wg.Done()

		}(rProxy, qmChan)
	}

	var qmArray []AvgRttQueryModel

	wg.Wait()
	close(qmChan)

	for qm := range qmChan {
		qmArray = append(qmArray, qm)
	}

	if len(qmArray) <= 0 {
		return nil, 0, fmt.Errorf("all servers failed to resolve")
	}
	sort.Slice(qmArray, func(i, j int) bool {
		return qmArray[i].ping > qmArray[j].ping
	})
	qm := qmArray[0]
	return qm.msg, qm.rtt, qm.err
}
func (wh *Wormhole) TestPing(address string) time.Duration {
	pinger, err := ping.NewPinger(address)
	if err != nil {
		return math.MaxInt32
	}
	pinger.Count = 5
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		return math.MaxInt32
	}
	stats := pinger.Statistics() // get send/receive/duplicate/rtt stats
	return stats.AvgRtt
}

func (wh *Wormhole) start() {
	log.Info("Initializing CoreDNS 'Wormhole' list update routines...")

	go wh.runFileUpdater()
	go wh.runHttpUpdater()
}

func (wh *Wormhole) runFileUpdater() {

	wh.handleFileUpdate()

	if wh.config.EnableAutoUpdate {
		wh.fileUpdateTicker = time.NewTicker(wh.config.FileListRenewalInterval)
		for range wh.fileUpdateTicker.C {
			wh.handleFileUpdate()
		}
	}

}

func (wh *Wormhole) handleFileUpdate() {

	fileSubscribeGroup, fileIgnoreSubscribeGroup := wh.getFilterFileSubscribeList()
	updateFileSubscribeGroup(fileSubscribeGroup)
	updateFileSubscribeGroup(fileIgnoreSubscribeGroup)
	if wh.ros != nil {
		wh.updateIP_CIDR_RouterOS(fileSubscribeGroup)
	}
}

func (wh *Wormhole) runHttpUpdater() {
	log.Info("Updating lists from HTTP URLs...")

	wh.handleHTTPListUpdate()

	if wh.config.EnableAutoUpdate {
		wh.httpUpdateTicker = time.NewTicker(wh.config.HttpListRenewalInterval)
		for range wh.httpUpdateTicker.C {
			wh.handleHTTPListUpdate()
			log.Infof("Scheduled next update of HTTP lists in %s at %s", wh.config.HttpListRenewalInterval.String(), time.Now().Add(wh.config.HttpListRenewalInterval).String())
		}
	}

}

func (wh *Wormhole) handleHTTPListUpdate() {
	log.Infof("Updating and Persisting HTTP lists...")

	httpSubscribeGroup, httpIgnoreSubscribeGroup := wh.getFilterHttpSubscribeList()
	updateHttpSubscribeList(httpSubscribeGroup)
	updateHttpSubscribeList(httpIgnoreSubscribeGroup)

	if wh.ros != nil {
		wh.updateIP_CIDR_RouterOS(httpSubscribeGroup)
	}

}

func (wh *Wormhole) updateIP_CIDR_RouterOS(subscribeGroup []*SubscribeRuleGroup) {
	for _, group := range subscribeGroup {
		ipcidrList := group.ip_CIDRList
		for _, cidrRule := range ipcidrList {
			target := cidrRule.Payload()

			var timeout int
			if group.subscribe.isOnlineSubscribe {
				timeout = int(wh.config.HttpListRenewalInterval.Seconds() - 1)
			} else {
				timeout = int(wh.config.FileListRenewalInterval.Seconds() - 1)
			}

			comment := group.subscribe.Url
			if wh.ros != nil {
				err := wh.ros.AddCIDRAddress(target, strconv.Itoa(timeout), comment)
				if err != nil {
					log.Errorf("%s", err)
				}
			}
		}
	}
}
