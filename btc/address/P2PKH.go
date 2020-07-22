package address

import (
	"encoding/hex"
	"errors"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"paper/common"
)

func NewP2PKH(rawPrivKey []byte, netType string, isCompress bool) (string, error) {
	//先检测函数参数的有效性
	var mapNet = map[string]byte{"testnet":0x6F, "main":0x00}
	if _, ok := mapNet[netType]; !ok {
		return "",errors.New("net type invalid")
	}

	var (
		privKey *secp256k1.PrivateKey
		err error
		pubKey []byte
		hash160 []byte
		hash160WithPrefix []byte
		address []byte
		hash256 [32]byte
	)

	//1. 用私钥生成公钥
	privKey = secp256k1.PrivKeyFromBytes(rawPrivKey)

	//2. 计算公钥
	if isCompress {
		pubKey, _ = hex.DecodeString(NewCompressPubKey(privKey.PubKey().X().Bytes(), privKey.PubKey().Y().Bytes()))
	} else {
		pubKey,_ = hex.DecodeString(NewUncompressPubKey(privKey.PubKey().X().Bytes(), privKey.PubKey().Y().Bytes()))
	}

	//3. 计算公钥的sha256哈希值
	//4. 计算上一步结果的ripemd160哈希值
	if hash160, err = common.Ripemd160AfterSha256(pubKey); err != nil {
		return "", err
	}

	//5. 取上一步结果，前面加入地址网络前缀
	hash160WithPrefix = append([]byte{mapNet[netType]}, hash160...)

	//6. 取上一步结果，计算SHA256哈希值
	//7. 取上一步结果，在计算SHA256哈希值
	hash256 = common.Sha256AfterSha256(hash160WithPrefix)

	//8. 取上一步结果的前四个字节，放在第五步结果后面，作为校验
	address = append(hash160WithPrefix, hash256[0:4]...)

	//9. 用base58编码上一步结果
	return base58.Encode(address),nil
}

// 需要调用方自己确保pubKeyHash的有效性
func MustPubKeyHash2Address(pubKeyHash []byte, addrType string) string {
	var prefix byte
	if addrType == "p2pkh" {
		prefix = 0
	} else if addrType == "p2sh" {
		prefix = 0x05
	} else if addrType == "testnet" {
		prefix = 0x6f
	}
	address := append([]byte{prefix}, pubKeyHash...)
	checksum := common.Sha256AfterSha256(address)
	address = append(address, checksum[:4]...)
	return base58.Encode(address)
}



