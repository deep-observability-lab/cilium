// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package amqp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/proxylib/proxylib"
)

type amqpRule struct {
	cmdExact          string
	fileRegexCompiled *regexp.Regexp
}

type amqpRequestData struct {
	cmd  string
	file string
}

func (rule *amqpRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	reqData, ok := data.(amqpRequestData)
	regexStr := ""
	if rule.fileRegexCompiled != nil {
		regexStr = rule.fileRegexCompiled.String()
	}

	if !ok {
		logrus.Warning("Matches() called with type other than amqpRequestData")
		return false
	}
	if len(rule.cmdExact) > 0 && rule.cmdExact != reqData.cmd {
		logrus.Debugf("amqpRule: cmd mismatch %s, %s", rule.cmdExact, reqData.cmd)
		return false
	}
	if rule.fileRegexCompiled != nil &&
		!rule.fileRegexCompiled.MatchString(reqData.file) {
		logrus.Debugf("amqpRule: file mismatch %s, %s", rule.fileRegexCompiled.String(), reqData.file)
		return false
	}
	logrus.Debugf("policy match for rule: '%s' '%s'", rule.cmdExact, regexStr)
	return true
}

// ruleParser parses protobuf L7 rules to enforcement objects
// May panic
func ruleParser(rule *cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return nil
	}

	allowRules := l7Rules.GetL7AllowRules()
	rules := make([]proxylib.L7NetworkPolicyRule, 0, len(allowRules))
	for _, l7Rule := range allowRules {
		var rr amqpRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "cmd":
				rr.cmdExact = v
			case "file":
				if v != "" {
					rr.fileRegexCompiled = regexp.MustCompile(v)
				}
			default:
				proxylib.ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if rr.cmdExact != "" &&
			rr.cmdExact != "READ" &&
			rr.cmdExact != "WRITE" &&
			rr.cmdExact != "HALT" &&
			rr.cmdExact != "RESET" {
			proxylib.ParseError(fmt.Sprintf("Unable to parse L7 amqp rule with invalid cmd: '%s'", rr.cmdExact), rule)
		}
		if (rr.fileRegexCompiled != nil) && !(rr.cmdExact == "" || rr.cmdExact == "READ" || rr.cmdExact == "WRITE") {
			proxylib.ParseError(fmt.Sprintf("Unable to parse L7 amqp rule, cmd '%s' is not compatible with 'file'", rr.cmdExact), rule)
		}
		regexStr := ""
		if rr.fileRegexCompiled != nil {
			regexStr = rr.fileRegexCompiled.String()
		}
		logrus.Debugf("Parsed rule '%s' '%s'", rr.cmdExact, regexStr)
		rules = append(rules, &rr)
	}
	return rules
}

type factory struct{}

func init() {
	logrus.Info("init(): Registering amqpParserFactory")
	proxylib.RegisterParserFactory("amqp", &factory{})
	proxylib.RegisterL7RuleParser("amqp", ruleParser)
}

type parser struct {
	connection *proxylib.Connection
}

func (f *factory) Create(connection *proxylib.Connection) interface{} {
	logrus.Debugf("amqpParserFactory: Create: %v", connection)

	return &parser{connection: connection}
}

func (p *parser) OnData(reply, endStream bool, dataArray [][]byte) (proxylib.OpType, int) {
	data := bytes.Join(dataArray, []byte{})

	// here we want to make sure we have at least 8 bytes of data
	if len(data) < 8 {
		logrus.Debugf("Not enough data, requesting more")
		return proxylib.MORE, 8 - len(data)
	}

	// processing the amqp header (first 8 bytes for starting the connection)
	firstFour := string(data[:4])
	if firstFour == "AMQP" {
		return proxylib.PASS, 8
	}

	frameType := data[0]
	channelID := binary.BigEndian.Uint16(data[1:3])
	frameSize := binary.BigEndian.Uint32(data[3:7])
	totalFrameSize := int(frameSize) + 8

	if len(data) < totalFrameSize {
		logrus.Debugf("Incomplete frame, requesting %d more bytes", totalFrameSize-len(data))
		return proxylib.MORE, totalFrameSize - len(data)
	}

	if reply {
		p.connection.Log(cilium.EntryType_Response, &cilium.LogEntry_GenericL7{
			GenericL7: &cilium.L7LogEntry{
				Proto: "AMQP",
				Fields: map[string]string{
					"frameType": fmt.Sprintf("%d", frameType),
					"channelID": fmt.Sprintf("%d", channelID),
					"frameSize": fmt.Sprintf("%d", frameSize),
				},
			},
		})
		return proxylib.PASS, totalFrameSize
	}

	p.connection.Log(cilium.EntryType_Request, &cilium.LogEntry_GenericL7{
		GenericL7: &cilium.L7LogEntry{
			Proto: "AMQP",
			Fields: map[string]string{
				"frameType": fmt.Sprintf("%d", frameType),
				"channelID": fmt.Sprintf("%d", channelID),
				"frameSize": fmt.Sprintf("%d", frameSize),
			},
		},
	})

	return proxylib.PASS, totalFrameSize
}
