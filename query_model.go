/*
 * @Author: Charley
 * @Date: 2021-08-20 17:25:57
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-20 17:26:41
 * @FilePath: /coredns/plugin/forward/query_model.go
 * @Description: dns 查询模型
 */
package wormhole

import (
	"time"

	"github.com/miekg/dns"
)

type QueryModel struct {
	msg *dns.Msg
	rtt time.Duration

	err error
}

func NewQueryModel(msg *dns.Msg, rtt time.Duration, err error) QueryModel {
	return QueryModel{
		msg: msg,
		rtt: rtt,
		err: err,
	}
}

type AvgRttQueryModel struct {
	msg  *dns.Msg
	rtt  time.Duration
	ping time.Duration

	err error
}

func NewAvgRttQueryModel(msg *dns.Msg, rtt, ping time.Duration, err error) AvgRttQueryModel {
	return AvgRttQueryModel{
		msg:  msg,
		rtt:  rtt,
		ping: ping,
		err:  err,
	}
}
