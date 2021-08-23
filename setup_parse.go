package wormhole

import (
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
)

func parsePluginConfiguration(c *caddy.Controller) (*WormholeConfig, error) {
	config := defaultPluginConfig

	toHost := c.RemainingArgs()
	config.RemoteServers = toHost

	rosTimeOut := "0"

	rosEnabledIPV6 := false

	for c.NextBlock() {
		switch c.Val() {
		case Config_Key_List:
			listArgs := c.RemainingArgs()
			if len(listArgs) != 2 {
				log.Warningf("Get List Config Error %s", listArgs)
				continue
			}

			subscribeFileTypeStr := listArgs[0]
			if subscribeFileTypeStr != Config_List_Key_Clash && subscribeFileTypeStr != Config_List_Key_Dnsmasq {
				log.Warningf("Subscribe File Type Error %s", subscribeFileTypeStr)
				continue
			}
			var subscribeFileType SubscribeFileType
			switch subscribeFileTypeStr {
			case Config_List_Key_Clash:
				subscribeFileType = SubscribeFileTypeClash
			case Config_List_Key_Dnsmasq:
				subscribeFileType = SubscribeFileTypeDnsmasq
			}

			subscribeFileUrlStr := listArgs[1]
			isOnlineSubscribe := false
			if strings.HasPrefix(subscribeFileUrlStr, "http://") || strings.HasPrefix(subscribeFileUrlStr, "https://") {
				isOnlineSubscribe = true
			}

			subscribe := SubscribeFile{
				Url:               subscribeFileUrlStr,
				isOnlineSubscribe: isOnlineSubscribe,
				FileType:          subscribeFileType,
			}
			config.SubscribeList = append(config.SubscribeList, subscribe)

		case Config_Key_Domain:

			domainList := c.RemainingArgs()
			config.DomainList = domainList

		case Config_Key_DomainSuffix:

			domainSuffixList := c.RemainingArgs()
			config.DomainSuffixList = domainSuffixList

		case Config_Key_DomainKeyword:

			domainKeywordList := c.RemainingArgs()
			config.DomainKeywordList = domainKeywordList
		case Config_Key_RegexlistRules:

			regexlistRulesList := c.RemainingArgs()
			config.RegexlistRules = regexlistRulesList

		case Config_Key_IgnoreList:
			listArgs := c.RemainingArgs()
			if len(listArgs) != 2 {
				log.Warningf("Get List Config Error %s", listArgs)
				continue
			}

			subscribeFileTypeStr := listArgs[0]
			if subscribeFileTypeStr != Config_List_Key_Clash && subscribeFileTypeStr != Config_List_Key_Dnsmasq {
				log.Warningf("Subscribe File Type Error %s", subscribeFileTypeStr)
				continue
			}
			var subscribeFileType SubscribeFileType
			switch subscribeFileTypeStr {
			case Config_List_Key_Clash:
				subscribeFileType = SubscribeFileTypeClash
			case Config_List_Key_Dnsmasq:
				subscribeFileType = SubscribeFileTypeDnsmasq
			}

			subscribeFileUrlStr := listArgs[1]

			isOnlineSubscribe := false
			if strings.HasPrefix(subscribeFileUrlStr, "http://") || strings.HasPrefix(subscribeFileUrlStr, "https://") {
				isOnlineSubscribe = true
			}

			subscribe := SubscribeFile{
				Url:               subscribeFileUrlStr,
				isOnlineSubscribe: isOnlineSubscribe,
				FileType:          subscribeFileType,
			}
			config.IgnoreSubscribeList = append(config.IgnoreSubscribeList, subscribe)

		case Config_Key_IgnoreDomain:

			domainList := c.RemainingArgs()
			config.IgnoreDomainList = domainList

		case Config_Key_IgnoreDomainSuffix:

			domainSuffixList := c.RemainingArgs()
			config.IgnoreDomainSuffixList = domainSuffixList

		case Config_Key_IgnoreDomainKeyword:

			domainKeywordList := c.RemainingArgs()
			config.IgnoreDomainKeywordList = domainKeywordList
		case Config_Key_IgnoreRegexlistRules:

			regexlistRulesList := c.RemainingArgs()
			config.IgnoreRegexlistRules = regexlistRulesList

		case Config_Key_HttpRenewalInterval:

			intervalArgs := c.RemainingArgs()
			if len(intervalArgs) <= 0 {
				log.Warning("Please enter HttpRenewalInterval Parameters")
				continue
			}
			tempInterval, err := strconv.ParseUint(intervalArgs[0], 10, 64)
			if err != nil {
				return nil, err
			}
			config.HttpListRenewalInterval = time.Duration(tempInterval) * time.Second

		case Config_Key_FileRenewalInterval:

			intervalArgs := c.RemainingArgs()
			if len(intervalArgs) <= 0 {
				log.Warning("Please enter FileRenewalInterval Parameters")
				continue
			}
			tempInterval, err := strconv.ParseUint(intervalArgs[0], 10, 64)
			if err != nil {
				return nil, err
			}
			config.FileListRenewalInterval = time.Duration(tempInterval) * time.Second

		case Config_Key_RetryCount:
			retryCountArgs := c.RemainingArgs()
			if len(retryCountArgs) <= 0 {
				log.Warning("Please enter Retry Count Parameters")
				continue
			}
			tempCount, err := strconv.Atoi(retryCountArgs[0])
			if err != nil {
				return nil, err
			}
			config.ListRenewalRetryCount = tempCount

		case Config_Key_RetryInterval:
			retryIntervalArgs := c.RemainingArgs()
			if len(retryIntervalArgs) <= 0 {
				log.Warning("Please enter Retry Interval Parameters")
				continue
			}
			tempInterval, err := strconv.ParseUint(retryIntervalArgs[0], 10, 64)
			if err != nil {
				return nil, err
			}
			config.ListRenewalRetryInterval = time.Duration(tempInterval) * time.Second

		case Config_Key_Policy:
			policyArgs := c.RemainingArgs()
			if len(policyArgs) <= 0 {
				log.Warning("Please enter Policy Parameters")
				continue
			}
			config.Policy = policyArgs[0]

		case Config_Key_DisableAutoUpdate:
			config.EnableAutoUpdate = false
		case Config_Key_RouterOS:
			rosArgs := c.RemainingArgs()

			if len(rosArgs) != 4 {
				log.Warning("Please enter the correct parameters")
				continue
			}

			ros := &RouterOSConfig{
				Host:     rosArgs[0],
				Username: rosArgs[1],
				Password: rosArgs[2],
				ListName: rosArgs[3],
			}

			ros.AddressTimeOut = rosTimeOut
			ros.Enabled_IPV6 = rosEnabledIPV6

			config.ROSConfig = ros
		case Config_Key_RouterOS_Timeout:
			rosTimeoutArgs := c.RemainingArgs()
			if len(rosTimeoutArgs) <= 0 {
				log.Warning("Please enter Policy Parameters")
				continue
			}

			if config.ROSConfig != nil {
				config.ROSConfig.AddressTimeOut = rosTimeoutArgs[0]
			} else {
				rosTimeOut = rosTimeoutArgs[0]
			}

		case Config_Key_RouterOS_Enabled_IPV6:

			if config.ROSConfig != nil {
				config.ROSConfig.Enabled_IPV6 = true
			} else {
				rosEnabledIPV6 = true
			}
		}
	}

	return &config, nil
}
