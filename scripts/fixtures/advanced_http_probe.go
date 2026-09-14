package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func httpProxyProbe(projector, address string) {
	tcpTarget, _, stop := echoServers(address)
	defer stop()
	for _, encrypted := range []bool{false, true} {
		port := localPort(address, "tcp")
		inbound := object{"type": "http", "tag": "server", "listen": address, "listen_port": port,
			"users": []any{object{"username": "fixture-user", "password": "fixture-password"}}}
		var roots *x509.CertPool
		var certificatePin, keyPin string
		tlsOptions := object{"enabled": true, "server_name": "connect.example.com"}
		if encrypted {
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			require(err == nil, "HTTP certificate key")
			certificate := &x509.Certificate{SerialNumber: big.NewInt(17), DNSNames: []string{"connect.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
			der := checked(x509.CreateCertificate(rand.Reader, certificate, certificate, pub, key))
			roots = x509.NewCertPool()
			roots.AddCert(checked(x509.ParseCertificate(der)))
			cpin := sha256.Sum256(der)
			certificatePin = base64.StdEncoding.EncodeToString(cpin[:])
			kpin := sha256.Sum256(checked(x509.ParseCertificate(der)).RawSubjectPublicKeyInfo)
			keyPin = base64.StdEncoding.EncodeToString(kpin[:])
			inbound["tls"] = object{"enabled": true, "certificate": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))},
				"key": []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: checked(x509.MarshalPKCS8PrivateKey(key))}))}}
		}
		server := start(object{"log": object{"level": "error"}, "inbounds": []any{inbound}, "outbounds": []any{object{"type": "direct", "tag": "direct"}}})
		node := object{"type": "http", "tag": "connect", "server": address, "server_port": port,
			"authentication": object{"username_credential_ref": object{"id": profileID, "kind": "http_proxy_username"}, "password_credential_ref": object{"id": sharedID, "kind": "http_proxy_password"}}}
		if encrypted {
			node["tls"] = tlsOptions
		}
		for _, scenario := range []string{"accepted", "bad-password", "bad-certificate", "certificate-pin", "key-pin", "wrong-pin", "pin-wrong-name"} {
			if !encrypted && scenario != "accepted" && scenario != "bad-password" {
				continue
			}
			node["tls"] = object{"enabled": true, "server_name": "connect.example.com"}
			if !encrypted {
				delete(node, "tls")
			}
			if encrypted {
				tls := node["tls"].(map[string]any)
				switch scenario {
				case "certificate-pin", "pin-wrong-name":
					tls["certificate_sha256"] = []string{certificatePin}
				case "key-pin":
					tls["certificate_public_key_sha256"] = []string{keyPin}
				case "wrong-pin":
					tls["certificate_sha256"] = []string{base64.StdEncoding.EncodeToString(make([]byte, 32))}
				}
				if scenario == "pin-wrong-name" {
					tls["server_name"] = "wrong.example.com"
				}
			}
			config := project(projector, object{"outbounds": []any{node}})
			prepareListeners(config, address)
			outbound := config["outbounds"].([]any)[0].(map[string]any)
			outbound["username"] = "fixture-user"
			outbound["password"] = "fixture-password"
			if scenario == "bad-password" {
				outbound["password"] = "wrong"
			}
			trusted := roots
			if scenario == "bad-certificate" || scenario == "certificate-pin" || scenario == "key-pin" || scenario == "wrong-pin" || scenario == "pin-wrong-name" {
				trusted = x509.NewCertPool()
			}
			client, _ := startWithContext(config, trusted)
			if scenario == "accepted" || scenario == "certificate-pin" || scenario == "key-pin" {
				tcpExchange(client, "connect", tcpTarget)
			} else {
				outbound, exists := client.Outbound().Outbound("connect")
				require(exists, "HTTP outbound missing")
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				conn, err := outbound.DialContext(ctx, "tcp", M.ParseSocksaddr(tcpTarget))
				if conn != nil {
					closeChecked(conn)
				}
				cancel()
				require(err != nil, "invalid HTTP authentication or TLS identity accepted")
			}
			outboundAPI, exists := client.Outbound().Outbound("connect")
			require(exists, "HTTP outbound missing")
			packet, err := outboundAPI.ListenPacket(context.Background(), M.ParseSocksaddr(tcpTarget))
			if packet != nil {
				closeChecked(packet)
			}
			require(err != nil, "HTTP CONNECT falsely advertised UDP")
			closeChecked(client)
		}
		closeChecked(server)
	}
	fmt.Println("PASS HTTP/HTTPS CONNECT, Basic authentication, wrong credentials/certificate and unsupported UDP")
}
