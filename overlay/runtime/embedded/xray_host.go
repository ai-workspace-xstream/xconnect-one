package embedded

import (
	"bytes"
	"fmt"
	"runtime/debug"
	"sync"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
)

type xrayHost struct {
	mu         sync.Mutex
	instance   *core.Instance
	configJSON []byte
}

func newXrayHost() *xrayHost {
	return &xrayHost{}
}

func (h *xrayHost) Start(config model.Config) error {
	raw, err := overlayruntime.RenderXrayConfig(config)
	if err != nil {
		return fmt.Errorf("render embedded xray config: %w", err)
	}
	return h.startJSON(raw)
}

func (h *xrayHost) Update(config model.Config) (bool, error) {
	raw, err := overlayruntime.RenderXrayConfig(config)
	if err != nil {
		return false, fmt.Errorf("render embedded xray config: %w", err)
	}
	h.mu.Lock()
	unchanged := h.instance != nil && bytes.Equal(h.configJSON, raw)
	h.mu.Unlock()
	if unchanged {
		return false, nil
	}
	if err := h.startJSON(raw); err != nil {
		return false, err
	}
	return true, nil
}

func (h *xrayHost) Restart(config model.Config) error {
	return h.Start(config)
}

func (h *xrayHost) startJSON(raw []byte) error {
	pbCfg, err := serial.LoadJSONConfig(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("decode embedded xray protobuf config: %w", err)
	}
	inst, err := core.New(pbCfg)
	if err != nil {
		return fmt.Errorf("create embedded xray instance: %w", err)
	}

	h.mu.Lock()
	if h.instance != nil {
		_ = h.instance.Close()
		h.instance = nil
	}
	h.mu.Unlock()

	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return fmt.Errorf("start embedded xray instance: %w", err)
	}

	h.mu.Lock()
	h.instance = inst
	h.configJSON = append([]byte(nil), raw...)
	h.mu.Unlock()

	debug.FreeOSMemory()
	return nil
}

func (h *xrayHost) Running() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.instance != nil
}

func (h *xrayHost) Close() error {
	h.mu.Lock()
	inst := h.instance
	h.instance = nil
	h.configJSON = nil
	h.mu.Unlock()
	if inst == nil {
		return nil
	}
	err := inst.Close()
	debug.FreeOSMemory()
	return err
}
