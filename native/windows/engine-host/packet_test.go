package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPacketAttachmentIsAClosedExactObject(t *testing.T) {
	valid := `{"handle":18446744073709551614,"name":"CFW-TUN-8c4fe63e-b108-4cb8-b422-fd9186cba252","mtu":9000}`
	var value packetAttachment
	if err := json.Unmarshal([]byte(valid), &value); err != nil || value.Handle != ^uint64(0)-1 || value.MTU != 9000 {
		t.Fatal("64-bit capability metadata changed", value, err)
	}
	for _, data := range []string{
		`null`, `[]`, `{}`, valid + `{}`,
		strings.Replace(valid, `"handle":`, `"Handle":`, 1),
		strings.Replace(valid, `"mtu":9000`, `"mtu":9000,"mtu":1500`, 1),
		strings.Replace(valid, `"mtu":9000`, `"mtu":null`, 1),
		strings.Replace(valid, `"mtu":9000`, `"mtu":9000,"path":"ignored"`, 1),
		strings.Replace(valid, `18446744073709551614`, `18446744073709551616`, 1),
		strings.Replace(valid, `18446744073709551614`, `1.5`, 1),
		strings.Replace(valid, `18446744073709551614`, `-1`, 1),
	} {
		if err := json.Unmarshal([]byte(data), &value); err == nil {
			t.Fatal("ambiguous packet attachment accepted", data)
		}
	}
}
