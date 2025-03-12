# wireguard based vpn

## Usage
```bash
go build .
sudo ./wgvpn
```
```bash
# link up and set ip
sudo ip link set wg0 up
sudo ip addr add 10.0.0.20/24 dev wg0
```

## Tips for developer
> ---
> ### `vendor/golang.zx2c4.com/wireguard/device/receive.go`
> - All packets received from the udp socket are handled here
> ### `vendor/golang.zx2c4.com/wireguard/device/send.go`
> - Handling of packet transmission is defined here
> ---
