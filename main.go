//go:build !windows

package main

import (
	"io"
	"log"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"

	wgconn "golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

func main() {
	var tun wgtun.Device = nil
	var err error = nil

	flagsDefault.ParseFlags()

	var createTUN = wgtun.CreateTUN
	if flagsDefault.DeviceAuto {
		createTUN = wgtun.CreateTUNAutoNamed
	}
	if tun, err = createTUN(flagsDefault.DeviceName, wgdevice.DefaultMTU); err != nil {
		log.Panic(err)
	}

	dev := wgdevice.NewDevice(tun, wgconn.NewDefaultBind(), wgdevice.NewLogger(wgdevice.LogLevelVerbose, ""))
	if file, err := os.OpenFile(flagsDefault.ConfigFile, os.O_RDONLY, 0); err != nil {
		log.Panic(err)
	} else {
		fbytes, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			log.Panic(err)
		} else {
			dev.IpcSet(string(fbytes))
		}
	}
	dev.Up()

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt)
	signal.Notify(term, unix.SIGTERM)

	select {
	case <-term:
	case <-dev.Wait():
	}

	dev.Close()
}
