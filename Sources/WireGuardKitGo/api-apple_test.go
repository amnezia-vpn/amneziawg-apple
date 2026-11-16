package main

import (
	"encoding/hex"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
	"os"
	"strings"
	"testing"
)

func TestSetConfigRejectsUnknownHandle(t *testing.T) {
	if result := setConfig(-1, ""); result != -int64(unix.EBADF) {
		t.Fatalf("unknown handle returned %d, expected EBADF", result)
	}
}

type routingTestTUN struct {
	done   chan struct{}
	events chan tun.Event
}

func (t *routingTestTUN) File() *os.File { return nil }
func (t *routingTestTUN) Read(_ [][]byte, _ []int, _ int) (int, error) {
	<-t.done
	return 0, os.ErrClosed
}
func (t *routingTestTUN) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }
func (t *routingTestTUN) MTU() (int, error)                       { return 1280, nil }
func (t *routingTestTUN) Name() (string, error)                   { return "routing-test", nil }
func (t *routingTestTUN) Events() <-chan tun.Event                { return t.events }
func (t *routingTestTUN) Close() error                            { close(t.done); close(t.events); return nil }
func (t *routingTestTUN) BatchSize() int                          { return 1 }

func TestRoutingUpdatePreservesPeerAndSupportsCompensation(t *testing.T) {
	testTun := &routingTestTUN{done: make(chan struct{}), events: make(chan tun.Event)}
	logger := device.NewLogger(device.LogLevelSilent, "test")
	dev := device.NewDevice(testTun, conn.NewDefaultBind(), logger)
	const handle int32 = 19001
	tunnelHandles[handle] = tunnelHandle{Device: dev, Logger: logger}
	defer func() { delete(tunnelHandles, handle); dev.Close() }()
	var key device.NoisePublicKey
	for i := range key {
		key[i] = 2
	}
	publicKey := hex.EncodeToString(key[:])
	initial := "private_key=" + strings.Repeat("01", 32) + "\npublic_key=" + publicKey + "\nallowed_ip=192.0.2.1/32\n"
	if code := setConfig(handle, initial); code != 0 {
		t.Fatalf("initial configuration: %d", code)
	}
	peer := dev.LookupPeer(key)
	if peer == nil {
		t.Fatal("missing initial peer")
	}
	prefix := "public_key=" + publicKey + "\nupdate_only=true\nreplace_allowed_ips=true\n"
	if code := setConfig(handle, prefix+"allowed_ip=192.0.2.1/32\nallowed_ip=198.51.100.0/24\n"); code != 0 {
		t.Fatalf("routing update: %d", code)
	}
	if dev.LookupPeer(key) != peer {
		t.Fatal("routing update replaced the peer")
	}
	config, err := dev.IpcGet()
	if err != nil || !strings.Contains(config, "allowed_ip=198.51.100.0/24\n") {
		t.Fatal("new prefix not present")
	}
	if code := setConfig(handle, prefix+"allowed_ip=203.0.113.1/32\ninvalid_field=true\n"); code == 0 {
		t.Fatal("invalid UAPI configuration acknowledged")
	}
	if code := setConfig(handle, prefix+"allowed_ip=192.0.2.1/32\n"); code != 0 {
		t.Fatalf("compensation: %d", code)
	}
	config, err = dev.IpcGet()
	if err != nil || !strings.Contains(config, "allowed_ip=192.0.2.1/32\n") || strings.Contains(config, "allowed_ip=203.0.113.1/32\n") {
		t.Fatal("compensation did not restore previous prefixes")
	}
	if dev.LookupPeer(key) != peer {
		t.Fatal("compensation replaced the peer")
	}
}
