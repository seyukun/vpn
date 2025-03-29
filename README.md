# wireguard based vpn

## Usage
```bash
go build .
cat <<EOF | tee -a
private_key=`wg genkey | base64 -d | xxd -p -c 32`
listen_port=51820
api_url=http://example.com:3000/api/v0.1-beta
api_authorization=Bearer 820c2cef2f3e54f04390a5934451598a7e5c988b29f3516f1f6adf9f8072b35ecf72402996eaeac9f870d0ee490d989d95e4d306b64142ae6ce7ccd92d3ea82f
stun=stun.l.google.com:19302
EOF
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
