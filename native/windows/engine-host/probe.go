package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/sagernet/sing-box/experimental/libbox"
)

type probeOptions struct {
	Proxies        []string `json:"proxies"`
	TimeoutMS      uint16   `json:"timeout_ms"`
	TargetURL      string   `json:"target_url"`
	ExpectedStatus string   `json:"expected_status"`
}

type probeResult struct {
	Name      string  `json:"name"`
	Delay     *uint32 `json:"delay"`
	ErrorKind *string `json:"error_kind"`
}

func decodeProbe(data []byte) (probeOptions, bool) {
	if len(data) == 0 || len(data) > 65536 {
		return probeOptions{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return probeOptions{}, false
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return probeOptions{}, false
		}
		switch key {
		case "proxies", "timeout_ms", "target_url", "expected_status":
		default:
			return probeOptions{}, false
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return probeOptions{}, false
		}
	}
	if len(seen) != 4 {
		return probeOptions{}, false
	}
	var options probeOptions
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&options) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF {
		return probeOptions{}, false
	}
	return options, true
}

func probeProfile(configuration, parameters []byte) (json.RawMessage, string) {
	options, valid := decodeProbe(parameters)
	if !valid {
		return nil, "invalid_probe"
	}
	names, err := json.Marshal(options.Proxies)
	if err != nil {
		return nil, "invalid_probe"
	}
	// Use the exact GA implementation: protocol-aware URL tests, per-node
	// timeout/error results, no inbound/controller/OS integration, and Close
	// before reply. The parent independently requires this worker's retirement.
	encoded, err := libbox.TestProfileProxiesWithTarget(string(configuration), string(names), int32(options.TimeoutMS), options.TargetURL, options.ExpectedStatus)
	if err != nil {
		if strings.Contains(err.Error(), "profile probe cleanup failed") {
			return nil, "probe_cleanup_failed"
		}
		return nil, "probe_failed"
	}
	if len(encoded) > 65536 {
		return nil, "probe_response_invalid"
	}
	var results []probeResult
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&results) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF || len(results) != len(options.Proxies) {
		return nil, "probe_response_invalid"
	}
	for index, result := range results {
		if result.Name != options.Proxies[index] || (result.Delay == nil) == (result.ErrorKind == nil) || (result.Delay != nil && *result.Delay == 0) {
			return nil, "probe_response_invalid"
		}
		if result.ErrorKind != nil && *result.ErrorKind != "timeout" && *result.ErrorKind != "not_found" && *result.ErrorKind != "probe_failed" {
			return nil, "probe_response_invalid"
		}
	}
	return json.RawMessage(encoded), ""
}
