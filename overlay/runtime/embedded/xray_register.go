package embedded

import (
	// Mandatory core runtime managers (dispatcher, log, inbound/outbound managers).
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"

	// Minimal proxy protocols for XConnect Zero client overlay:
	// UDP/TCP dokodemo-door loopback inbound + VLESS/Freedom outbounds.
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"

	// Minimal transports: XHTTP + TLS/XTLS + TCP + UDP (keepalive sockopt).
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"

	// JSON config decoder used to hydrate core.Config in memory.
	_ "github.com/xtls/xray-core/main/json"
)
