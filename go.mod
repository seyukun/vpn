module vpn

go 1.24.1

require (
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/net v0.37.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

require (
	golang.org/x/sys v0.31.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
)

replace golang.zx2c4.com/wireguard => ./replace/golang.zx2c4.com/wireguard
