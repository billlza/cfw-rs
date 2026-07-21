# General

CFW-aligned settings list (not a dashboard card cluster). Each row matches Clash for Windows 0.20.39 macOS General affordances:

- **Port** — copy proxy `export` commands; random mixed-port; editable mixed-port
- **Allow LAN** — info, network interfaces, editable bind address, toggle
- **Log Level / IPv6** — level select / toggle
- **Clash Core** — preview runtime `config.yaml`, DNS query via controller, Script-mode note; version + controller port; start/stop/install
- **Home Directory / GeoIP Database** — Open Folder; click-to-update GeoIP
- **Service Mode** — status icon; Manage → Install / Uninstall / Login Items. Install also creates a writable `/Library/Application Support/com.bill.clashformac` control-session directory (admin prompt once) so TUN can hand the core to the root helper.
- **TUN Mode** — info, TUN settings (stack / auto-route / strict-route / dns-hijack), restore DNS after TUN off. Can stay on together with System Proxy. Failed TUN enable rolls `tun_mode` back on disk so other toggles cannot ghost-flip the switch.
- **Mixin** — info, edit Mixin YAML, toggle
- **System Proxy / Start with macOS** — toggles

Sidebar still shows live up/down rates, running time, and Connected status.
