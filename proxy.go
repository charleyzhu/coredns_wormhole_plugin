/*
 * @Author: Charley
 * @Date: 2021-08-17 17:30:46
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-20 15:32:12
 * @FilePath: /coredns/plugin/wormhole/proxy.go
 * @Description: 转发代理
 */
package wormhole

import (
	"time"

	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/miekg/dns"
)

type Proxy struct {
	Client *dns.Client
	host   string

	// fails uint32

	// // health checking
	// probe  *up.Probe
	// health HealthChecker
}

func (p *Proxy) Query(m *dns.Msg) (*dns.Msg, time.Duration, error) {
	return p.Client.Exchange(m, p.host)
}

// func (p *Proxy) Healthcheck() {
// 	if p.health == nil {
// 		log.Warning("No healthchecker")
// 		return
// 	}

// 	p.probe.Do(func() error {
// 		return p.health.Check(p)
// 	})
// }

// func (p *Proxy) Down(maxfails uint32) bool {
// 	if maxfails == 0 {
// 		return false
// 	}

// 	fails := atomic.LoadUint32(&p.fails)
// 	return fails > maxfails
// }

func NewProxy(trans, addr string) *Proxy {
	dnsClient := new(dns.Client)
	remoteServer := new(dns.Client)
	switch trans {
	case transport.DNS:
		remoteServer.Net = "udp"
	case transport.TLS:
		remoteServer.Net = "tcp-tls"
	}
	return &Proxy{Client: dnsClient, host: addr}
}
