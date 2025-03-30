# wireguard based vpn

## Usage

You need to get a token from http://example.com:3000/api/v0.1-beta/signup  
\* Symmetric NAT not yet supported

```bash
git clone git@github.com:seyukun/vpn.git
cd vpn
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

# For windows users
you need to install `wintun.dll`. https://www.wintun.net/

```ps1
git clone git@github.com:seyukun/vpn.git
cd vpn
go build .
# edit .config
# install gsudo
curl -sLO https://www.wintun.net/builds/wintun-0.14.1.zip
tar -xf .\wintun-0.14.1.zip
cp wintun\bin\amd64\wintun.dll .\
rm -r -fo .\wintun
rm -r -fo .\wintun-0.14.1.zip
sudo .\vpn
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
