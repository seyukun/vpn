# wireguard based vpn

## Usage
```bash
go build .
sudo ./wgvpn
```
```bash
sudo ip link set wg0 up
sudo ip addr add 10.0.0.20/24 dev wg0
```
