package address

import (
	"encoding/hex"
)

func NewCompressPubKey(X []byte, Y []byte) string {
	//前缀03+x(如果y是奇数)，前缀02+x(如果y是偶数)
	var prefix byte
	if Y[len(Y)-1] %2 != 0 {
		prefix = 0x3
	} else {
		prefix = 0x2
	}
	var pubKeyInBytes []byte
	pubKeyInBytes = append([]byte{prefix}, X...)
	return hex.EncodeToString(pubKeyInBytes)
}

func NewUncompressPubKey(X []byte, Y []byte) string {
	//0X04 + X + Y
	var pubKeyInBytes []byte
	pubKeyInBytes = append([]byte{0x04}, X...)
	pubKeyInBytes = append(pubKeyInBytes, Y...)
	return hex.EncodeToString(pubKeyInBytes)
}

