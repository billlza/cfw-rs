package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func probeRequest(t *testing.T, config string, options probeOptions) request {
	t.Helper()
	data, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	return request{Protocol: protocol, Session: testSession, ID: 2, Op: "probe", Digest: testDigest, Config: json.RawMessage(config), Probe: data}
}
func runProbe(t *testing.T, value request) (int, response) {
	t.Helper()
	var output bytes.Buffer
	code := run(bytes.NewReader(messages(t, hello(), value)), &output)
	replies := responses(t, output.Bytes())
	if len(replies) != 2 {
		t.Fatalf("expected one terminal probe reply: %+v", replies)
	}
	return code, replies[1]
}

func TestProfileProbeUsesRealHTTPAndExactStatusWithoutRuntimeStart(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.Path != "/probe" {
			t.Errorf("unexpected probe request: %s %s", r.Method, r.URL.Path)
		}
		requests.Add(1)
		w.WriteHeader(204)
	}))
	defer server.Close()
	config := `{"outbounds":[{"type":"direct","tag":"direct"}]}`
	options := probeOptions{[]string{"direct", "missing"}, 1000, server.URL + "/probe", "204"}
	code, reply := runProbe(t, probeRequest(t, config, options))
	if code != 0 || reply.State != "probed" || reply.Digest != testDigest || reply.Error != "" || reply.ID != 2 || reply.PID <= 0 || reply.Session != testSession {
		t.Fatalf("probe was not a successful terminal operation: %d %+v", code, reply)
	}
	var rows []probeResult
	if err := json.Unmarshal(reply.Results, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Name != "direct" || rows[0].Delay == nil || *rows[0].Delay == 0 || rows[0].ErrorKind != nil || rows[1].Name != "missing" || rows[1].Delay != nil || rows[1].ErrorKind == nil || *rows[1].ErrorKind != "not_found" {
		t.Fatalf("protocol/outcome/ordering changed: %+v", rows)
	}
	options.Proxies = []string{"direct"}
	options.ExpectedStatus = "200"
	code, reply = runProbe(t, probeRequest(t, config, options))
	if code != 0 || json.Unmarshal(reply.Results, &rows) != nil || len(rows) != 1 || rows[0].Delay != nil || rows[0].ErrorKind == nil || *rows[0].ErrorKind != "probe_failed" || requests.Load() != 2 {
		t.Fatalf("HTTP status mismatch was presented as latency success: %d %+v", code, reply)
	}
}

func TestProfileProbeRejectsIntegrationAndMalformedOptions(t *testing.T) {
	options := probeOptions{[]string{"direct"}, 100, "http://127.0.0.1:1/", "204"}
	for _, configuration := range []string{
		`{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}`,
		`{"experimental":{"cache_file":{"enabled":true}}}`,
		`{"route":{"auto_detect_interface":true}}`,
		`{"outbounds":[{"type":"tor","tag":"secret-do-not-echo"}]}`,
	} {
		code, reply := runProbe(t, probeRequest(t, configuration, options))
		if code == 0 || reply.State == "probed" || len(reply.Results) != 0 || reply.Error != "probe_failed" {
			t.Fatalf("integration admitted: %+v", reply)
		}
	}
	for _, raw := range []string{
		`null`, `{}`, `{"proxies":["direct"],"timeout_ms":100,"target_url":"","expected_status":"","extra":true}`,
		`{"proxies":["direct"],"timeout_ms":100,"target_url":"","expected_status":"","timeout_ms":200}`,
		`{"proxies":["direct"],"timeout_ms":100,"target_url":null,"expected_status":""}`,
		`{"proxies":null,"timeout_ms":100,"target_url":"","expected_status":""}`,
	} {
		value := probeRequest(t, `{}`, options)
		value.Probe = json.RawMessage(raw)
		code, reply := runProbe(t, value)
		if code == 0 || reply.Error != "invalid_probe" || len(reply.Results) != 0 {
			t.Fatalf("malformed probe metadata admitted: %+v", reply)
		}
	}
	for _, options := range []probeOptions{
		{[]string{"direct", "direct"}, 100, "", ""}, {[]string{}, 100, "", ""}, {[]string{"direct"}, 99, "", ""},
		{[]string{"direct"}, 100, "https://name:secret@localhost/", ""}, {[]string{"direct"}, 100, "", "600"},
	} {
		code, reply := runProbe(t, probeRequest(t, `{}`, options))
		if code == 0 || reply.Error != "probe_failed" || len(reply.Results) != 0 {
			t.Fatalf("invalid probe contract admitted: %+v", reply)
		}
	}
}

func TestProfileProbeCannotRunInsideAnOwnedRuntime(t *testing.T) {
	config := `{"outbounds":[{"type":"direct","tag":"direct"}]}`
	probe := probeRequest(t, config, probeOptions{[]string{"direct"}, 100, "", ""})
	probe.ID = 3
	var output bytes.Buffer
	if run(bytes.NewReader(messages(t, hello(), request{protocol, testSession, 2, "start", testDigest, json.RawMessage(config), nil, nil}, probe)), &output) == 0 {
		t.Fatal("probe ran inside active runtime")
	}
	replies := responses(t, output.Bytes())
	if len(replies) != 3 || replies[2].Error != "invalid_probe" || len(replies[2].Results) != 0 {
		t.Fatalf("invalid active probe receipt: %+v", replies)
	}
	value := hello()
	value.Probe = probe.Probe
	output.Reset()
	if run(bytes.NewReader(messages(t, value)), &output) == 0 || output.Len() != 0 {
		t.Fatal("hello admitted probe parameters")
	}
}

func TestProfileProbeLargerReplyKeepsRuntimeFramesBounded(t *testing.T) {
	names := make([]string, 32)
	for i := range names {
		names[i] = fmt.Sprintf("%02d-", i) + strings.Repeat("n", 500)
	}
	code, reply := runProbe(t, probeRequest(t, `{}`, probeOptions{names, 100, "", ""}))
	if code != 0 || len(reply.Results) <= 4096 || len(reply.Results) > 65536 {
		t.Fatalf("large bounded result failed: %d %+v", code, reply)
	}
	var rows []probeResult
	if json.Unmarshal(reply.Results, &rows) != nil || len(rows) != 32 {
		t.Fatal("result count changed")
	}
	for i, row := range rows {
		if row.Name != names[i] || row.ErrorKind == nil || *row.ErrorKind != "not_found" {
			t.Fatal("ordered missing node result changed")
		}
	}
	var out bytes.Buffer
	if writeResponse(&out, response{State: "running", Error: strings.Repeat("x", 4096)}) == nil {
		t.Fatal("normal runtime frame bound widened")
	}
}
