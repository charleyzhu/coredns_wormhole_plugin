/*
 * @Author: Charley
 * @Date: 2021-08-17 17:30:46
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-23 16:27:35
 * @FilePath: /coredns/plugin/wormhole/proxy.go
 * @Description: 转发代理
 */
package wormhole

import (
	"fmt"
	"strings"
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
	if len(m.Question) > 0 {
		domain := m.Question[0].Name
		if strings.HasPrefix(domain, "https://") {
			domain = strings.Replace(domain, "https://", "", 1)
			m.Question[0].Name = domain
		}

		if strings.HasPrefix(domain, "http://") {
			domain = strings.Replace(domain, "http://", "", 1)
			m.Question[0].Name = domain
		}

		return p.Client.Exchange(m, p.host)
	}
	return m, 0, fmt.Errorf("query question length error")

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
