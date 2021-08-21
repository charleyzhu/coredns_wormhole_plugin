/*
 * @Author: Charley
 * @Date: 2021-08-20 14:54:48
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-20 17:36:20
 * @FilePath: /coredns/plugin/wormhole/policy.go
 * @Description: 负载顺序
 */
package wormhole

type Policy int

const (
	PolicyBalancing Policy = iota
	PolicyParallel
	PolicyFastTest
)

func (p Policy) String() string {
	switch p {
	case PolicyBalancing:
		return "Balancing"
	case PolicyParallel:
		return "Parallel"
	case PolicyFastTest:
		return "FastTest"
	default:
		return "Unknown"
	}
}
