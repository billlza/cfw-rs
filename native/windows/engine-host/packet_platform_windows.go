package main

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"golang.org/x/sys/windows"
)

var errPacketPlatform = errors.New("operation is not owned by the Windows packet platform")

type packetPlatform struct {
	device *packetDevice
	opened atomic.Bool
}

var _ adapter.PlatformInterface = (*packetPlatform)(nil)

func openPacketRuntime(attachment packetAttachment) (packetRuntime, error) {
	if uint64(uintptr(attachment.Handle)) != attachment.Handle {
		return nil, errPacketContract
	}
	device, err := newPacketDevice(windows.Handle(attachment.Handle), attachment.Name, attachment.MTU)
	if err != nil {
		return nil, err
	}
	return &packetPlatform{device: device}, nil
}

func (p *packetPlatform) Prepare(ctx context.Context, options option.Options) (context.Context, error) {
	count := 0
	for _, inbound := range options.Inbounds {
		if inbound.Type != "tun" {
			continue
		}
		count++
		value, ok := inbound.Options.(*option.TunInboundOptions)
		if !ok || value == nil || value.MTU != uint32(p.device.mtu) ||
			(value.InterfaceName != "" && value.InterfaceName != p.device.name) ||
			value.Stack != "gvisor" || !tun.WithGVisor || value.AutoRoute || value.AutoRedirect ||
			value.StrictRoute || value.NetNs != "" || value.DNSMode == tun.DNSModeNative ||
			(value.Platform != nil && value.Platform.HTTPProxy != nil) {
			return nil, errPacketPlatform
		}
	}
	if count != 1 {
		return nil, errPacketPlatform
	}
	return service.ContextWith[adapter.PlatformInterface](ctx, p), nil
}

func (p *packetPlatform) Failure() error { return p.device.Failure() }
func (p *packetPlatform) Close() error   { return p.device.Close() }

func (p *packetPlatform) Initialize(adapter.NetworkManager) error { return nil }
func (p *packetPlatform) UsePlatformInterface() bool              { return true }
func (p *packetPlatform) OpenInterface(options *tun.Options, platform option.TunPlatformOptions) (tun.Tun, error) {
	if options.MTU != uint32(p.device.mtu) || options.AutoRoute || options.StrictRoute ||
		options.NetNs != "" || options.FileDescriptor != 0 || platform.HTTPProxy != nil || !p.opened.CompareAndSwap(false, true) {
		return nil, errPacketPlatform
	}
	// The authority's retained adapter chooses the name. No interface is
	// created/opened by name, and no route, DNS setting or firewall is changed.
	options.Name = p.device.name
	return p.device, nil
}
func (p *packetPlatform) ProcessPlatformOptions(options option.TunPlatformOptions) error {
	if options.HTTPProxy != nil {
		return errPacketPlatform
	}
	return nil
}

// All unrelated platform overrides are disabled. The pinned engine retains
// its normal Windows interface discovery, process lookup and socket routing.
func (p *packetPlatform) UsePlatformAutoDetectInterfaceControl() bool { return false }
func (p *packetPlatform) AutoDetectInterfaceControl(int) error        { return errPacketPlatform }
func (p *packetPlatform) UsePlatformDefaultInterfaceMonitor() bool    { return false }
func (p *packetPlatform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return nil // No override was advertised.
}
func (p *packetPlatform) UsePlatformNetworkInterfaces() bool { return false }
func (p *packetPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	return nil, errPacketPlatform
}
func (p *packetPlatform) UnderNetworkExtension() bool              { return false }
func (p *packetPlatform) NetworkExtensionIncludeAllNetworks() bool { return false }
func (p *packetPlatform) UsePlatformConnectionOwnerFinder() bool   { return false }
func (p *packetPlatform) UsePlatformWIFIMonitor() bool             { return false }
func (p *packetPlatform) RequestPermissionForWIFIState() error     { return errPacketPlatform }
func (p *packetPlatform) ReadWIFIState(context.Context) adapter.WIFIState {
	return adapter.WIFIState{} // UsePlatformWIFIMonitor is false.
}
func (p *packetPlatform) FindConnectionOwner(*adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, errPacketPlatform
}

// Router.ClearCache already clears sing-box's actual DNS and reverse caches.
// This adapter owns no additional platform cache or resolver configuration.
func (p *packetPlatform) ClearDNSCache()                               {}
func (p *packetPlatform) MyInterfaceAddress() []netip.Addr             { return nil }
func (p *packetPlatform) UsePlatformNotification() bool                { return false }
func (p *packetPlatform) SendNotification(*adapter.Notification) error { return errPacketPlatform }
func (p *packetPlatform) CancelNotification(string, int32) error       { return errPacketPlatform }
func (p *packetPlatform) UsePlatformNeighborResolver() bool            { return false }
func (p *packetPlatform) StartNeighborMonitor(adapter.NeighborUpdateListener) error {
	return errPacketPlatform
}
func (p *packetPlatform) CloseNeighborMonitor(adapter.NeighborUpdateListener) error {
	return errPacketPlatform
}
func (p *packetPlatform) UsePlatformShell() bool    { return false }
func (p *packetPlatform) CheckPlatformShell() error { return errPacketPlatform }
func (p *packetPlatform) OpenShellSession(*adapter.PlatformUser, string, []string, string, int32, int32) (adapter.ShellSession, error) {
	return nil, errPacketPlatform
}
func (p *packetPlatform) LookupUser(string) (*adapter.PlatformUser, error) {
	return nil, errPacketPlatform
}
func (p *packetPlatform) LookupSFTPServer() (string, error)     { return "", errPacketPlatform }
func (p *packetPlatform) ReadSystemSSHHostKey() ([]byte, error) { return nil, errPacketPlatform }
func (p *packetPlatform) TailscaleHostname() string             { return "" }
func (p *packetPlatform) UsePlatformBridge() bool               { return false }
func (p *packetPlatform) CreateBridge(adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, errPacketPlatform
}
