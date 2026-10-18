package main

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

var errPrivate = errors.New("private forwarder unavailable")

type privatePolicy struct {
	Proxy string
	MTU   int
}

func parsePolicy(data []byte) (privatePolicy, error) {
	var result privatePolicy
	if len(data) == 0 || len(data) > 8192 || !utf8.Valid(data) {
		return result, errPrivate
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var node yaml.Node
	if decoder.Decode(&node) != nil || len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode || node.Content[0].Tag != "!!map" || node.Content[0].Anchor != "" || len(node.Content[0].Content) != 6 {
		return result, errPrivate
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return result, errPrivate
	}
	seen := map[string]bool{}
	items := node.Content[0].Content
	for i := 0; i < len(items); i += 2 {
		key, value := items[i], items[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" || value.Kind != yaml.ScalarNode || value.Anchor != "" || seen[key.Value] {
			return result, errPrivate
		}
		seen[key.Value] = true
		switch key.Value {
		case "proxy":
			if value.Tag != "!!str" {
				return result, errPrivate
			}
			result.Proxy = value.Value
		case "mtu":
			if value.Tag != "!!int" || value.Value != "1500" {
				return result, errPrivate
			}
			result.MTU = 1500
		case "loglevel":
			if value.Tag != "!!str" || value.Value != "error" {
				return result, errPrivate
			}
		default:
			return result, errPrivate
		}
	}
	if !seen["proxy"] || !seen["mtu"] || !seen["loglevel"] {
		return result, errPrivate
	}
	u, err := url.Parse(result.Proxy)
	if err != nil || u.Scheme != "socks5" || u.Opaque != "" || u.User == nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return result, errPrivate
	}
	peer, err := netip.ParseAddrPort(u.Host)
	if err != nil || peer.Addr() != netip.MustParseAddr("127.0.0.1") || peer.Port() == 0 || u.Host != "127.0.0.1:"+strconv.Itoa(int(peer.Port())) {
		return result, errPrivate
	}
	password, ok := u.User.Password()
	if !ok || !utf8.ValidString(u.User.Username()) || !utf8.ValidString(password) || len(u.User.Username()) < 1 || len(u.User.Username()) > 255 || len(password) < 1 || len(password) > 255 {
		return result, errPrivate
	}
	return result, nil
}
