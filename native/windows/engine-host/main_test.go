package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
)

const testSession = "0123456789abcdef0123456789abcdef"
const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func frame(data []byte) []byte {
	result := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(result, uint32(len(data)))
	copy(result[4:], data)
	return result
}

func messages(t *testing.T, requests ...request) []byte {
	t.Helper()
	var result []byte
	for _, value := range requests {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, frame(encoded)...)
	}
	return result
}

func responses(t *testing.T, data []byte) []response {
	t.Helper()
	reader := bytes.NewReader(data)
	var result []response
	for reader.Len() > 0 {
		var header [4]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			t.Fatal(err)
		}
		size := binary.LittleEndian.Uint32(header[:])
		if size > 4096 {
			t.Fatal("oversized response")
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(reader, body); err != nil {
			t.Fatal(err)
		}
		var value response
		if err := json.Unmarshal(body, &value); err != nil {
			t.Fatal(err)
		}
		result = append(result, value)
	}
	return result
}

func hello() request { return request{Protocol: protocol, Session: testSession, ID: 1, Op: "hello"} }

func TestOwnedInstanceStartsObservesAndCloses(t *testing.T) {
	input := messages(t, hello(),
		request{protocol, testSession, 2, "start", testDigest, json.RawMessage(`{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"}]}`)},
		request{protocol, testSession, 3, "observe", testDigest, nil},
		request{protocol, testSession, 4, "stop", testDigest, nil})
	var output bytes.Buffer
	if code := run(bytes.NewReader(input), &output); code != 0 {
		t.Fatalf("exit %d: %s", code, output.Bytes())
	}
	replies := responses(t, output.Bytes())
	if len(replies) != 4 {
		t.Fatalf("reply count: %d", len(replies))
	}
	for index, state := range []string{"idle", "running", "running", "stopped"} {
		value := replies[index]
		if value.State != state || value.Error != "" || value.ID != uint64(index+1) || value.PID <= 0 || value.Session != testSession {
			t.Fatalf("invalid response: %+v", value)
		}
		if index > 0 && value.Digest != testDigest {
			t.Fatal("projection identity changed")
		}
	}
}

func TestMalformedFramesAndClosedEnvelope(t *testing.T) {
	valid, _ := json.Marshal(hello())
	for name, data := range map[string][]byte{
		"empty":          nil,
		"partial_header": {1, 2},
		"zero":           {0, 0, 0, 0},
		"oversized":      {1, 0x10, 0x40, 0},
		"truncated":      {4, 0, 0, 0, '{'},
		"bad_utf8":       frame([]byte{0xff}),
		"array":          frame([]byte(`[]`)),
		"duplicate":      frame([]byte(`{"protocol":1,"protocol":1}`)),
		"unknown":        frame([]byte(`{"unknown":true}`)),
		"case_alias":     frame([]byte(`{"Protocol":1,"protocol":1}`)),
		"trailing":       frame(append(valid, []byte(` {}`)...)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readRequest(bytes.NewReader(data)); err == nil {
				t.Fatal("malformed request accepted")
			}
		})
	}
}

func TestStaleIdentityAndSequenceCannotControlInstance(t *testing.T) {
	for _, wrong := range []request{
		{2, testSession, 2, "observe", "", nil},
		{protocol, strings.Repeat("a", 32), 2, "observe", "", nil},
		{protocol, testSession, 1, "observe", "", nil},
		{protocol, testSession, 2, "hello", "", nil},
	} {
		var output bytes.Buffer
		if run(bytes.NewReader(messages(t, hello(), wrong)), &output) == 0 {
			t.Fatal("invalid identity accepted")
		}
		if len(responses(t, output.Bytes())) != 1 {
			t.Fatal("invalid request received an operation receipt")
		}
	}
}

func TestConfigurationFailureIsExplicitAndRedacted(t *testing.T) {
	for _, configuration := range []string{
		`{"outbounds":[{"type":"secret-unsupported-protocol"}]}`,
		`{"log":{"output":"stdout"}}`,
		`{"log":{"output":"secret-log-path"}}`,
	} {
		for _, operation := range []string{"start", "check"} {
			var output bytes.Buffer
			input := messages(t, hello(), request{protocol, testSession, 2, operation, testDigest, json.RawMessage(configuration)})
			if run(bytes.NewReader(input), &output) == 0 {
				t.Fatal("bad config accepted")
			}
			replies := responses(t, output.Bytes())
			if len(replies) != 2 || replies[1].Error == "" || replies[1].State != "idle" {
				t.Fatal("missing failure receipt")
			}
			if strings.Contains(output.String(), "secret-") {
				t.Fatal("configuration echoed in response")
			}
		}
	}
}

func TestCheckConstructsAndClosesWithoutOpeningListeners(t *testing.T) {
	// Holding both ports makes an accidental Start fail, rather than letting a
	// momentarily active proxy pass a post-exit listener-only assertion.
	mixed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mixed.Close()
	controller, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	configuration := json.RawMessage(`{"log":{"disabled":true},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":` + strconv.Itoa(mixed.Addr().(*net.TCPAddr).Port) + `}],"outbounds":[{"type":"direct","tag":"direct"}],"experimental":{"clash_api":{"external_controller":"` + controller.Addr().String() + `","secret":"check-only-secret"}}}`)
	var output bytes.Buffer
	if code := run(bytes.NewReader(messages(t, hello(), request{protocol, testSession, 2, "check", testDigest, configuration})), &output); code != 0 {
		t.Fatalf("check failed: %d, %s", code, output.Bytes())
	}
	replies := responses(t, output.Bytes())
	if len(replies) != 2 || replies[1].State != "checked" || replies[1].Error != "" || replies[1].Digest != testDigest || replies[1].PID <= 0 {
		t.Fatalf("missing exact check receipt: %+v", replies)
	}
	if strings.Contains(output.String(), "check-only-secret") {
		t.Fatal("check echoed credential material")
	}
}

func TestCheckCannotValidateAnActiveInstanceOrMalformedCandidate(t *testing.T) {
	configuration := json.RawMessage(`{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"}]}`)
	for _, input := range [][]byte{
		messages(t, hello(), request{protocol, testSession, 2, "check", "bad-digest", configuration}),
		messages(t, hello(), request{protocol, testSession, 2, "check", testDigest, nil}),
		messages(t, hello(), request{protocol, testSession, 2, "start", testDigest, configuration}, request{protocol, testSession, 3, "check", testDigest, configuration}),
	} {
		var output bytes.Buffer
		if run(bytes.NewReader(input), &output) == 0 {
			t.Fatal("invalid check accepted")
		}
		replies := responses(t, output.Bytes())
		last := replies[len(replies)-1]
		if last.Error != "invalid_check" || last.State == "checked" || last.State == "stopped" {
			t.Fatalf("false check receipt: %+v", last)
		}
	}
}

func TestEOFAndInvalidOperationsCannotProduceStoppedReceipt(t *testing.T) {
	for _, op := range []string{"stop", "observe", "unsupported"} {
		var output bytes.Buffer
		input := messages(t, hello(), request{protocol, testSession, 2, op, testDigest, nil})
		if run(bytes.NewReader(input), &output) == 0 {
			t.Fatal("operation accepted without running engine")
		}
		for _, value := range responses(t, output.Bytes()) {
			if value.State == "stopped" {
				t.Fatal("false stopped receipt")
			}
		}
	}
	var output bytes.Buffer
	if run(bytes.NewReader(messages(t, hello())), &output) == 0 {
		t.Fatal("EOF treated as normal stop")
	}
}
