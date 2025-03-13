package main

import (
	"io"
	"log"
	"os"
	"os/signal"

	wgconn "golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

func main() {
	var tun wgtun.Device = nil
	var err error = nil

	flagsDefault.ParseFlags()

	if flagsDefault.DeviceAuto {
		tun, err = createTunAutoNamed(flagsDefault.DeviceName, wgdevice.DefaultMTU)
	} else {
		tun, err = wgtun.CreateTUN(flagsDefault.DeviceName, wgdevice.DefaultMTU)
	}
	if err != nil {
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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	dev.Down()
}
