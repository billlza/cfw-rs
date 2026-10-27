package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/sagernet/sing-box/option"
)

// This is bootstrap metadata on the owned control channel, not a field in a
// user profile. The launcher has to inherit the exact endpoint before hello.
type packetAttachment struct {
	Handle uint64 `json:"handle"`
	Name   string `json:"name"`
	MTU    uint32 `json:"mtu"`
}

func (p *packetAttachment) UnmarshalJSON(data []byte) error {
	if len(data) > 256 {
		return errors.New("packet_attachment_size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("packet_attachment_object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] || (name != "handle" && name != "name" && name != "mtu") {
			return errors.New("packet_attachment_key")
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("packet_attachment_value")
		}
	}
	if len(seen) != 3 {
		return errors.New("packet_attachment_missing")
	}
	type plain packetAttachment
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode((*plain)(p)); err != nil {
		return err
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return errors.New("packet_attachment_trailing")
	}
	return nil
}

type packetRuntime interface {
	Prepare(context.Context, option.Options) (context.Context, error)
	Failure() error
	Close() error
}

func hasTunnel(options option.Options) bool {
	for _, inbound := range options.Inbounds {
		if inbound.Type == "tun" {
			return true
		}
	}
	return false
}
