package main

import (
	"flag"
)

type Flags struct {
	DeviceName string
	ConfigFile string
}

var flagsDefault = Flags{}

func (FlagsDefault *Flags) ParseFlags() {
	deviceName := flag.String("device", "wg", "Name of the device")
	configFile := flag.String("config", ".config", "Path to the configuration file")
	flag.Parse()
	FlagsDefault.DeviceName = *deviceName
	FlagsDefault.ConfigFile = *configFile
}
