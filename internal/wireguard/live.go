package wireguard

import (
	"context"
	"strconv"
	"strings"
	"time"
)

func GetLiveStatus(configuredInterface string) WireGuardLiveStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	raw, err := execWG(ctx, "wg", "show", "interfaces")
	if err != nil || strings.TrimSpace(raw) == "" {
		return WireGuardLiveStatus{Up: false}
	}
	actual := pickInterface(raw, configuredInterface, configuredInterface)
	if actual == "" {
		return WireGuardLiveStatus{Up: false}
	}

	dump, err := execWG(ctx, "wg", "show", actual, "dump")
	if err != nil {
		ifName := actual
		return WireGuardLiveStatus{Up: true, InterfaceName: &ifName}
	}
	lines := strings.Split(strings.TrimSpace(dump), "\n")
	if len(lines) == 0 {
		ifName := actual
		return WireGuardLiveStatus{Up: true, InterfaceName: &ifName}
	}
	first := strings.Split(lines[0], "\t")
	var listen *int
	if len(first) >= 3 {
		if n, err := strconv.Atoi(first[2]); err == nil {
			listen = &n
		}
	}
	ifName := actual
	return WireGuardLiveStatus{Up: true, InterfaceName: &ifName, ListenPort: listen}
}

