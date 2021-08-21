/*
 * @Author: Charley
 * @Date: 2021-08-18 09:01:27
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-19 15:49:21
 * @FilePath: /coredns/plugin/wormhole/setup_test.go
 * @Description: In User Settings Edit
 */
package wormhole

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		// 配置文件内容
		input string
		// 是否应该报错
		shouldErr bool
	}{
		{"clash https://192.168.3.9", false},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		_, err := parseWormhole(c)
		if test.shouldErr && err == nil {
			t.Errorf("Test %d: expected error but found %s for input %s", i, err, test.input)
		}
	}
}
