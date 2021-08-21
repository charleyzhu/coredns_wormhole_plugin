/*
 * @Author: Charley
 * @Date: 2021-08-18 15:26:38
 * @LastEditors: Charley
 * @LastEditTime: 2021-08-20 16:02:47
 * @FilePath: /coredns/plugin/wormhole/wormhole_config.go
 * @Description: 配置模型定义
 */
package wormhole

import "time"

type SubscribeFileType int

// 订阅文件类型
const (
	// clash订阅的域名列表
	SubscribeFileTypeClash SubscribeFileType = iota
	// dnsmasq类型的文件列表
	SubscribeFileTypeDnsmasq
)

// 订阅文件
type SubscribeFile struct {
	Url               string
	isOnlineSubscribe bool
	FileType          SubscribeFileType
}

// 配置文件
type WormholeConfig struct {
	// 转发的dns服务器
	RemoteServers []string

	SubscribeList     []SubscribeFile // 订阅列表
	DomainList        []string        // 自定义域名列表
	DomainSuffixList  []string        // 自定义主域列表
	DomainKeywordList []string        // 自定义域名中的关键字列表
	RegexlistRules    []string        // 用于匹配的正则表达式列表

	IgnoreSubscribeList     []SubscribeFile //订阅忽略的文件列表
	IgnoreDomainList        []string        // 自定义忽略域名列表
	IgnoreDomainSuffixList  []string        // 自定义忽略主域列表
	IgnoreDomainKeywordList []string        // 自定义忽略域名中的关键字列表
	IgnoreRegexlistRules    []string        // 用于匹配忽略的正则表达式列表

	Policy string

	HttpListRenewalInterval  time.Duration //http订阅的更新间隔时间
	FileListRenewalInterval  time.Duration //本地文件更新间隔时间
	ListRenewalRetryCount    int           //遇到错误以后重试的次数
	ListRenewalRetryInterval time.Duration //遇到错误以后重试的间隔时间

	EnableAutoUpdate bool // 是否开启自动更新
}
