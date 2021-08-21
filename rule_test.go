package wormhole

import (
	"testing"

	"github.com/miekg/dns"
)

type TestCase struct {
	Domain  string
	IsMatch bool
}

func TestRule(t *testing.T) {

	tests := []struct {
		input           string
		shouldErr       bool
		expectedIgnored bool
		testCases       []TestCase
	}{
		{"PROCESS-NAME,com.google.android.youtube", false, true, []TestCase{{"", false}}},
		{"PROCESS-NAME,com.google.android.youtube.tv", false, true, []TestCase{{"", false}}},
		{"DOMAIN-KEYWORD,youtube", false, false, []TestCase{{"www.youtube.com", true}, {"www.google.com", false}}},
		{"DOMAIN,yt3.ggpht.com", false, false, []TestCase{{"yt3.ggpht.com", true}, {"www.google.com", false}}},
		{"DOMAIN-SUFFIX,googlevideo.com", false, false, []TestCase{{"yt3.googlevideo.com", true}, {"yt3.google.com", false}}},
		{"DOMAIN-SUFFIX,gvt2.com", false, false, []TestCase{{"yt3.gvt2.com", true}, {"yt3.google.com", false}}},
		{"DOMAIN-SUFFIX,youtu.be", false, false, []TestCase{{"yt3.youtu.be", true}, {"yt3.gvt2.com", false}}},
		{"DOMAIN-SUFFIX,ytimg.com", false, false, []TestCase{{"yt3.ytimg.com", true}, {"yt3.gvt2.com", false}}},
		{"www.youtube.com", true, false, []TestCase{{"yt3.ytimg.com", true}, {"yt3.gvt2.com", false}}},
	}

	for i, test := range tests {
		rule, err := parseClashRulesLine(test.input)
		if test.shouldErr && err == nil {
			t.Errorf("Test %d: expected error but found %s for input %s", i, err, test.input)
		}

		if !test.expectedIgnored && (err == nil && rule == nil) {
			t.Errorf("Test %d: expected error but found RuleType for input: %s", i, test.input)
		}

		if rule == nil {
			continue
		}

		for j, testCase := range test.testCases {
			emptyMsg := &dns.Msg{}
			emptyMsg.Question = append(emptyMsg.Question, dns.Question{
				Name:   testCase.Domain + ".",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			})
			isMacth := rule.Match(emptyMsg)

			if isMacth != testCase.IsMatch {
				t.Errorf("Test %d: TestCase %d expected error but found RuleType for input: %s RuleType:%s test domain:%s", i, j, test.input, rule.RuleType(), testCase.Domain)
			}
		}

	}
}
