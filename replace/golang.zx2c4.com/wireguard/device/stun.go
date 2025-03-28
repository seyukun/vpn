/* ******************************************************************************************************************** */
/*                                                                                                                      */
/*                                                      :::    :::     :::     :::     :::   ::: ::::::::::: :::::::::: */
/*   stun.go                                           :+:   :+:    :+: :+:   :+:     :+:   :+:     :+:     :+:         */
/*                                                    +:+  +:+    +:+   +:+  +:+      +:+ +:+      +:+     +:+          */
/*   By: yus-sato <yus-sato@kalyte.ro>               +#++:++    +#++:++#++: +#+       +#++:       +#+     +#++:++#      */
/*                                                  +#+  +#+   +#+     +#+ +#+        +#+        +#+     +#+            */
/*   Created: 2025/03/29 02:27:22 by yus-sato      #+#   #+#  #+#     #+# #+#        #+#        #+#     #+#             */
/*   Updated: 2025/03/29 04:16:17 by yus-sato     ###    ### ###     ### ########## ###        ###     ##########.ro    */
/*                                                                                                                      */
/* ******************************************************************************************************************** */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	StunResponseType         = 0x0101
	stunMagicCookie          = 0x2112A442
	stunXorMappedAddressType = 0x0020
)

type Stun struct {
	transactionId []byte
}

var stun = Stun{
	transactionId: make([]byte, 12),
}

/*
# STUN HEADER FORMAT
used in both requests and responses

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|     STUN Message Type     |         Message Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Cookie                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Transaction ID (96 bits)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

=> 160bits => 20 bytes
*/

func (stun *Stun) InitTransactionId() (err error) {
	if _, err := rand.Read(stun.transactionId); err != nil {
		return err
	}
	return nil
}

func (stun *Stun) CreateStunBindingRequest() (req []byte, transactionId []byte, err error) {
	req = make([]byte, 20)                                // 160 bits
	binary.BigEndian.PutUint16(req[0:2], 0x0001)          // 0 ~ 15 bit  (Message Type)
	binary.BigEndian.PutUint16(req[2:4], 0)               // 16 ~ 31 bit (Message Length)
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie) // 32 ~ 63 bit (Magic Cookie)
	copy(req[8:20], stun.transactionId)                   // 64 ~ 159 bit (Transaction ID)
	return req, stun.transactionId, nil
}

/*
# STUN RESPONSE BODY FORMAT
used in responses only

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Type                  |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Value (variable) (min 8 bytes)   ....
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

func (stun *Stun) ParseStunBindingResponse(resp []byte) (ip net.IP, port int, err error) {
	if resp[0]>>6 != 0 || len(resp) < 20 {
		return nil, 0, errors.New("STUN response length is insufficient")
	}

	msgType := binary.BigEndian.Uint16(resp[:2])
	msgLength := binary.BigEndian.Uint16(resp[2:4])
	respCookie := binary.BigEndian.Uint32(resp[4:8])
	respTransactionId := resp[8:20]

	if respCookie != stunMagicCookie {
		return nil, 0, errors.New("STUN response has invalid magic cookie")
	} else if string(respTransactionId) != string(stun.transactionId) {
		return nil, 0, errors.New("STUN response has invalid transaction id")
	} else if msgType != 0x0101 {
		return nil, 0, errors.New("STUN response has invalid message type")
	} else if len(resp) < int(20+msgLength) {
		return nil, 0, errors.New("STUN response has invalid message length")
	}

	offset := 20
	for offset+4 <= int(20+msgLength) {
		attrType := binary.BigEndian.Uint16(resp[offset : offset+2])     // 0 ~ 15 bit (Type)
		attrLength := binary.BigEndian.Uint16(resp[offset+2 : offset+4]) // 16 ~ 31 bit (Length)
		if offset+4+int(attrLength) > len(resp) {
			return nil, 0, errors.New("attribute length is too long")
		}
		attrValue := resp[offset+4 : offset+4+int(attrLength)]

		// Discover XOR-MAPPED-ADDRESS attribute
		if attrType == stunXorMappedAddressType {
			// Attribute value format (for IPv4):
			// 0: Reserved (0x00)
			// 1: Address Family (0x01: IPv4, 0x02: IPv6)
			// 2-3: X-Port
			// 4-7: X-Address (for IPv4)
			if len(attrValue) < 8 {
				return nil, 0, errors.New("insufficient length of XOR-MAPPED-ADDRESS attribute")
			}
			family := attrValue[1]
			xport := binary.BigEndian.Uint16(attrValue[2:4])
			// ポートは、X-PortとMagic Cookieの上位16ビットとのXORで復元
			port := xport ^ (uint16(stunMagicCookie >> 16))
			if family == 0x01 { // IPv4
				ip := net.IPv4(
					attrValue[4]^byte((stunMagicCookie>>24)&0xff),
					attrValue[5]^byte((stunMagicCookie>>16)&0xff),
					attrValue[6]^byte((stunMagicCookie>>8)&0xff),
					attrValue[7]^byte(stunMagicCookie&0xff),
				)
				return ip, int(port), nil
			} else if family == 0x02 { // IPv6 (Attribute length must be at least 20 bytes)
				if len(attrValue) < 20 {
					return nil, 0, errors.New("insufficient length of XOR-MAPPED-ADDRESS attribute for IPv6")
				}
				ip := make(net.IP, net.IPv6len)
				// The first four bytes are XORed with the Magic Cookie
				ip[0] = attrValue[4] ^ byte((stunMagicCookie>>24)&0xff)
				ip[1] = attrValue[5] ^ byte((stunMagicCookie>>16)&0xff)
				ip[2] = attrValue[6] ^ byte((stunMagicCookie>>8)&0xff)
				ip[3] = attrValue[7] ^ byte(stunMagicCookie&0xff)
				// The remaining 12 bytes are XORed with the Transaction Id
				for i := 0; i < 12; i++ {
					ip[4+i] = attrValue[8+i] ^ stun.transactionId[i]
				}
				return ip, int(port), nil
			} else {
				return nil, 0, fmt.Errorf("invalid address family: %d", family)
			}
		}

		// next attribute: each attribute is padded to align on a 4-byte boundary
		offset += 4 + int(attrLength)
		if mod := int(attrLength) % 4; mod != 0 {
			offset += 4 - mod
		}
	}
	return nil, 0, errors.New("XOR-MAPPED-ADDRESS attribute not found")
}
