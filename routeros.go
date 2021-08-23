/*
 * @Author: Charley
 * @Date: 2021-08-23 09:56:26
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-23 11:49:06
 * @FilePath: /coredns/plugin/wormhole/routeros.go
 * @Description: ROS 相关定义
 */
package wormhole

import (
	"fmt"

	sdkros "github.com/go-routeros/routeros"

	"github.com/miekg/dns"
)

type RouterOS struct {
	config *RouterOSConfig
	client *sdkros.Client
}

// func (ros *RouterOS) Dial() {

// }

// func (ros *RouterOS) isConnected() bool {}

func (ros *RouterOS) AddAddress(msg *dns.Msg) error {
	client, err := sdkros.Dial(ros.config.Host, ros.config.Username, ros.config.Password)
	if err != nil {
		return fmt.Errorf("dial routeros %s rind error %s", ros.config.Host, err)
	}

	defer client.Close()
	for _, r := range msg.Answer {
		if r.Header().Rrtype == dns.TypeA {
			rr := r.(*dns.A)
			address := rr.A.String()
			domain := rr.Hdr.Name
			_, err := client.Run("/ip/firewall/address-list/add", fmt.Sprintf("=address=%s", address),
				fmt.Sprintf("=list=%s", ros.config.ListName), fmt.Sprintf("=timeout=%s", ros.config.AddressTimeOut), fmt.Sprintf("=comment=%s", domain))
			if err != nil {
				return fmt.Errorf("run add ipv4 command routeros %s rind error %s", ros.config.Host, err)
			}

		} else if ros.config.Enabled_IPV6 && r.Header().Rrtype == dns.TypeAAAA {
			rr := r.(*dns.AAAA)
			address := rr.AAAA.String()
			domain := rr.Hdr.Name
			_, err := client.Run("/ipv6/firewall/address-list/add", fmt.Sprintf("=address=%s", address),
				fmt.Sprintf("=list=%s", ros.config.ListName), fmt.Sprintf("=timeout=%s", ros.config.AddressTimeOut), fmt.Sprintf("=comment=%s", domain))
			if err != nil {
				return fmt.Errorf("run add ipv6 command routeros %s rind error %s", ros.config.Host, err)

			}

		}

	}

	return nil
}

func NewRouterOS(cfg *RouterOSConfig) *RouterOS {

	return &RouterOS{
		config: cfg,
	}
}
