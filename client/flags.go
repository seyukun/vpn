package main

import (
	"flag"
)

type Flags struct {
	DeviceName string
	DeviceAuto bool
	ConfigFile string
}

var flagsDefault = Flags{}

func (flags *Flags) ParseFlags() {
	deviceName := flag.String("device", "wg", "Name of the device")
	deviceAuto := flag.Bool("auto", false, "Automatically create a device")
	configFile := flag.String("config", ".config", "Path to the configuration file")
	flag.Parse()
	flags.DeviceName = *deviceName
	flags.DeviceAuto = *deviceAuto
	flags.ConfigFile = *configFile
}
