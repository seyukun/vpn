package main

import (
	"io"
	"log"
	"os"
	"os/signal"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func main() {
	tun, err := tun.CreateTUN("wg0", device.DefaultMTU)
	if err != nil {
		log.Panic(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	if file, err := os.OpenFile(".config", os.O_RDONLY, 0); err != nil {
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
