package main

import (
	"fmt"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

func createTunAutoNamed(name string, mtu int) (wgtun.Device, error) {
	for i := 0; i < 100; i++ {
		tun, err := wgtun.CreateTUN(fmt.Sprintf("utun%d", i), mtu)
		if err != nil {
			continue
		}
		return tun, nil
	}

	return nil, fmt.Errorf("failed to create a device")
}
