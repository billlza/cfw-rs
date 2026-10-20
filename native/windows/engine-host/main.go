// The Windows process owner speaks only framed messages over inherited pipes.
// It is not an elevated service, a system-proxy owner, or a TUN authority.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"unicode/utf8"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

const protocol = 1
const maxConfig = 4 * 1024 * 1024
const maxRequest = maxConfig + 4096
const maxProbeRequest = maxConfig + 65536

type request struct {
	Protocol int             `json:"protocol"`
	Session  string          `json:"session"`
	ID       uint64          `json:"id"`
	Op       string          `json:"op"`
	Digest   string          `json:"digest,omitempty"`
	Config   json.RawMessage `json:"config,omitempty"`
	Probe    json.RawMessage `json:"probe,omitempty"`
}

type response struct {
	Protocol int             `json:"protocol"`
	Session  string          `json:"session"`
	ID       uint64          `json:"id"`
	PID      int             `json:"pid"`
	Version  string          `json:"version"`
	State    string          `json:"state"`
	Digest   string          `json:"digest"`
	Error    string          `json:"error"`
	Results  json.RawMessage `json:"results,omitempty"`
}

func readRequest(r io.Reader) (request, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return request{}, err
	}
	size := binary.LittleEndian.Uint32(header[:])
	if size == 0 || size > maxProbeRequest {
		return request{}, errors.New("frame_size")
	}
	data := make([]byte, size)
	defer clear(data)
	if _, err := io.ReadFull(r, data); err != nil {
		return request{}, err
	}
	if !utf8.Valid(data) {
		return request{}, errors.New("frame_encoding")
	}
	// The envelope is a closed object with no ambiguous duplicate fields. The
	// sing-box decoder independently validates the configuration's own schema.
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return request{}, errors.New("envelope_object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return request{}, errors.New("envelope_key")
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return request{}, errors.New("envelope_duplicate")
		}
		switch name {
		case "protocol", "session", "id", "op", "digest", "config", "probe":
		default:
			return request{}, errors.New("envelope_field")
		}
		seen[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			clear(value)
			return request{}, errors.New("envelope_value")
		}
		clear(value)
	}
	var result request
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		clear(result.Config)
		return request{}, errors.New("envelope_schema")
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		clear(result.Config)
		return request{}, errors.New("envelope_trailing")
	}
	if size > maxRequest && (result.Op != "probe" || len(result.Probe) == 0) {
		clear(result.Config)
		return request{}, errors.New("frame_size")
	}
	return result, nil
}

func writeResponse(w io.Writer, value response) error {
	data, err := json.Marshal(value)
	limit := 4096
	if value.State == "probed" && value.Error == "" && len(value.Results) != 0 {
		limit = 65536
	}
	if err != nil || len(data) > limit {
		return errors.New("response_encoding")
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(data)))
	if _, err = w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func canonicalHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && hex.EncodeToString(decoded) == value
}

// run is deliberately sequential: only one owned engine, one outstanding
// operation, and one terminal shutdown. No reconnect adopts an existing PID.
func run(input io.Reader, output io.Writer) int {
	var instance *box.Box
	var cancel context.CancelFunc
	defer func() {
		if instance != nil {
			// EOF/protocol failure is emergency cleanup, never a stopped receipt.
			_ = instance.Close()
		}
		if cancel != nil {
			cancel()
		}
	}()
	session, state, digest := "", "idle", ""
	var sequence uint64
	for {
		message, err := readRequest(input)
		if err != nil {
			return 2
		}
		sequence++
		valid := message.Protocol == protocol && message.ID == sequence && canonicalHex(message.Session, 16)
		if session == "" {
			valid = valid && message.Op == "hello"
			session = message.Session
		} else {
			valid = valid && message.Session == session && message.Op != "hello"
		}
		if !valid {
			clear(message.Config)
			return 2
		}
		errorCode := ""
		terminal := false
		var results json.RawMessage
		if message.Op != "probe" && len(message.Probe) != 0 {
			clear(message.Config)
			return 2
		}
		switch message.Op {
		case "hello":
			if len(message.Config) != 0 || message.Digest != "" {
				errorCode = "invalid_request"
			}
		case "start", "check":
			if state != "idle" || len(message.Config) == 0 || len(message.Config) > maxConfig || !canonicalHex(message.Digest, 32) {
				errorCode = "invalid_" + message.Op
				break
			}
			ctx, release := context.WithCancel(include.Context(context.Background()))
			cancel = release
			options, parseErr := singjson.UnmarshalExtendedContext[option.Options](ctx, message.Config)
			if parseErr != nil {
				errorCode = "invalid_config"
				break
			}
			// stdout belongs exclusively to this control protocol. Product
			// projections use stderr; accepting a file/stdout override here would
			// either persist secrets or corrupt control frames.
			if options.Log != nil && options.Log.Output != "" && options.Log.Output != "stderr" {
				errorCode = "invalid_log_output"
				break
			}
			instance, err = box.New(box.Options{Context: ctx, Options: options})
			if err != nil {
				errorCode = "construct_failed"
				break
			}
			if message.Op == "check" {
				// Match the actual engine's check path, but also require Close
				// success. Never call Start or issue a running/stopped receipt.
				closeErr := instance.Close()
				instance = nil
				cancel()
				cancel = nil
				if closeErr != nil {
					errorCode = "close_failed"
				} else {
					state, digest = "checked", message.Digest
					terminal = true
				}
				break
			}
			if err = instance.Start(); err != nil {
				errorCode = "start_failed"
				break
			}
			state, digest = "running", message.Digest
		case "probe":
			if state != "idle" || len(message.Config) == 0 || len(message.Config) > maxConfig || !canonicalHex(message.Digest, 32) {
				errorCode = "invalid_probe"
				break
			}
			results, errorCode = probeProfile(message.Config, message.Probe)
			if errorCode == "" {
				state, digest = "probed", message.Digest
				terminal = true
			}
		case "observe":
			if state != "running" || len(message.Config) != 0 || message.Digest != digest {
				errorCode = "invalid_observation"
			}
		case "stop":
			if state != "running" || len(message.Config) != 0 || message.Digest != digest {
				errorCode = "invalid_stop"
				break
			}
			closeErr := instance.Close()
			instance = nil
			cancel()
			cancel = nil
			if closeErr != nil {
				errorCode = "close_failed"
			} else {
				state = "stopped"
				terminal = true
			}
		default:
			errorCode = "invalid_operation"
		}
		clear(message.Config)
		reply := response{protocol, session, sequence, os.Getpid(), C.Version, state, digest, errorCode, results}
		if writeResponse(output, reply) != nil || errorCode != "" {
			return 2
		}
		if terminal {
			return 0
		}
	}
}

func main() {
	os.Exit(run(os.Stdin, os.Stdout))
}
