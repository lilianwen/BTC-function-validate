package address

import (
	"github.com/btcsuite/btcutil/base58"
	"paper/common"
)

func NewPrivKeyInWIF(privKey []byte, isCompress bool) string {
	//1. 添加前缀0x80（主网是0x80，测试网是0xef）todo:添加对测试网的支持
	privKey = append([]byte{0x80}, privKey...)
	if isCompress {
		privKey = append(privKey, byte(0x01))
	}

	//2. 取两次sha256哈希的前4个字节，作为校验值添加在后面
	hash256 := common.Sha256AfterSha256(privKey)
	privKey = append(privKey, hash256[:4]...)

	//3.用base58转换一下
	return base58.Encode(privKey)
}

func DecodeWIF(privk string) []byte {
	buf := base58.Decode(privk)
	return buf[1:33]
}

