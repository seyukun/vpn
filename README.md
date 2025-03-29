# wireguard based vpn

## Usage

You need to get a token from http://example.com:3000/api/v0.1-beta/signup

```bash
go build .
cat <<EOF | tee -a .config
private_key=`wg genkey | base64 -d | xxd -p -c 32`
listen_port=51820
api_url=http://example.com:3000/api/v0.1-beta
api_authorization=Bearer $TOKEN
stun=stun.l.google.com:19302
EOF
sudo ./vpn
```

## Tips for developer

> ---
>
> ### `vendor/golang.zx2c4.com/wireguard/device/receive.go`
>
> - All packets received from the udp socket are handled here
>
> ### `vendor/golang.zx2c4.com/wireguard/device/send.go`
>
> - Handling of packet transmission is defined here
>
> ---
