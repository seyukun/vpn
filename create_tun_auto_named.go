package main

import (
	"fmt"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

func createTunAutoNamed(name string, mtu int) (wgtun.Device, error) {
	var tun wgtun.Device = nil
	var err error = nil

	for i := 0; i < 100; i++ {
		if tun, err = wgtun.CreateTUN(fmt.Sprintf("utun%d", i), mtu); err != nil {
			continue
		} else {
			return tun, nil
		}
	}

	return nil, err
}
