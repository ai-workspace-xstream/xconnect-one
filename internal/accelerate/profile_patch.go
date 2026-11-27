package accelerate

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// decodeProfileWithSystemRoutes patches the generated Xray JSON profile for
// platforms (macOS, Windows) where Xray's TUN inbound manages system routes
// and binds outbound sockets to the physical default interface automatically.
func decodeProfileWithSystemRoutes(raw []byte, ifaceName string, routes []string) (*core.Config, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, errors.New("could not decode the selected Xray profile")
	}
	inbounds, ok := doc["inbounds"].([]any)
	if !ok || len(inbounds) == 0 {
		return nil, errors.New("could not decode the selected Xray profile")
	}
	inbound, ok := inbounds[0].(map[string]any)
	if !ok {
		return nil, errors.New("could not decode the selected Xray profile")
	}
	settings, ok := inbound["settings"].(map[string]any)
	if !ok {
		return nil, errors.New("could not decode the selected Xray profile")
	}
	settings["name"] = ifaceName
	if len(routes) > 0 {
		settings["autoSystemRoutingTable"] = routes
	}
	patched, err := json.Marshal(doc)
	if err != nil {
		return nil, errors.New("could not encode the selected Xray profile")
	}
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(patched))
	if err != nil {
		return nil, errors.New("could not decode the selected Xray profile")
	}
	return cfg, nil
}
