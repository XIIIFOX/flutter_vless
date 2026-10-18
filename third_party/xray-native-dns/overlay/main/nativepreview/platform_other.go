//go:build !android

package main

// Desktop loopback CI validates the native entry and ownership only. OS socket
// bypass (NE/WFP) belongs to its host and remains explicitly unqualified.
func prepareHost() error { return nil }
