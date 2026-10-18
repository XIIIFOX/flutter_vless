package main

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func testArguments() []string {
	path, _ := filepath.Abs("private-canary.json")
	return []string{"run", "--config", path,
		"--resolver", "127.0.0.1:53", "--egress-index", "1", "--capability", launcherCapability}
}

func TestNativeLauncherPolicyArguments(t *testing.T) {
	args := testArguments()
	before := append([]string(nil), args...)
	options, err := parseOptions(args)
	if err != nil || options.sourceIndex != 1 || options.resolver != "127.0.0.1:53" || options.timeout != 4*time.Second {
		t.Fatal("valid trusted literal policy rejected", err)
	}
	if !reflect.DeepEqual(args, before) {
		t.Fatal("parent arguments mutated")
	}
	args = append(args, "--timeout-ms", "4000")
	args[4] = "[::1]:5353"
	options, err = parseOptions(args)
	if err != nil || options.resolver != "[::1]:5353" || options.timeout != 4*time.Second {
		t.Fatal("literal IPv6 policy parse", err)
	}
}

func TestNativeLauncherRejectsUntrustedOrAmbiguousPolicy(t *testing.T) {
	cases := [][]string{nil, {"run"}, {"capabilities", "--config", "private"}, {"unknown"}}
	for _, replacement := range []struct {
		index int
		value string
	}{
		{2, "relative-private.json"}, {4, "resolver-private.invalid:53"}, {4, "127.0.0.1:0"},
		{4, "127.0.0.1:65536"}, {4, "127.0.0.1"}, {4, "[fe80::1%private]:53"},
		{6, "-1"}, {6, "private-index"}, {8, "legacy-capability"},
	} {
		args := testArguments()
		args[replacement.index] = replacement.value
		cases = append(cases, args)
	}
	for _, extra := range [][]string{{"--config", "private"}, {"--unknown", "private"}, {"--timeout-ms", "0"},
		{"--timeout-ms", "4001"}, {"--timeout-ms"}, {"--egress-index", "2"}} {
		cases = append(cases, append(testArguments(), extra...))
	}
	for index, args := range cases {
		if _, err := parseOptions(args); err != errArguments {
			t.Fatalf("case %d did not return the closed error", index)
		}
	}
}
