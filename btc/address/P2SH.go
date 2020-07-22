package address

import (
	"encoding/hex"
	"errors"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"paper/common"
)

/*
func NewP2SH(rawPrivKey []byte, netType string, isCompress bool) (string, error) {
	//先检测函数参数的有效性
	var mapNet = map[string]byte{"testnet":0x6F, "main":0x05}
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

	fmt.Println(hex.EncodeToString(pubKey))
	fmt.Println("03526ad084495e27d8e77a4b6f75e088734959f10a9df3e68751f1ae4c732114ed")


	//3. 计算公钥的sha256哈希值
	//4. 计算上一步结果的ripemd160哈希值
	if hash160, err = Ripemd160AfterSha256(pubKey); err != nil {
		return "", err
	}

	//5. 取上一步结果，前面加入地址网络前缀
	hash160WithPrefix = append([]byte{mapNet[netType]}, hash160...)

	//6. 取上一步结果，计算SHA256哈希值
	//7. 取上一步结果，在计算SHA256哈希值
	hash256 = Sha256AfterSha256(hash160WithPrefix)

	//8. 取上一步结果的前四个字节，放在第五步结果后面，作为校验
	address = append(hash160WithPrefix, hash256[:4]...)

	//9. 用base58编码上一步结果
	return base58.Encode(address),nil
}


 */

//P2WPKH-P2SH
func NewP2SH(rawPrivKey []byte, netType string, isCompress bool) (string, error) {
	//参数校验
	var mapNet = map[string]byte{"main":0x05, "testnet":0x6f}
	if _, ok := mapNet[netType]; !ok {
		return "", errors.New("invalid net type")
	}

	var (
		privKey *secp256k1.PrivateKey
		err error
		hash160 []byte
		pubKey []byte
	)

	privKey = secp256k1.PrivKeyFromBytes(rawPrivKey)

	//计算公钥
	if isCompress {
		pubKey, _ = hex.DecodeString(NewCompressPubKey(privKey.PubKey().X().Bytes(), privKey.PubKey().Y().Bytes()))
	} else {
		pubKey,_ = hex.DecodeString(NewUncompressPubKey(privKey.PubKey().X().Bytes(), privKey.PubKey().Y().Bytes()))
	}
	// BASE58CHECK( 0x05 HASH160( 0x00 0x14 HASH160( pubKey ) ) )
	//上面的 HASH160(x) = RIPEMD160(Sha256(x)），base58check(x) = x Sha256(Sha256(x)).substring(0,4)
	if hash160, err = common.Ripemd160AfterSha256(pubKey); err != nil {
		return "", err
	}

	if hash160, err = common.Ripemd160AfterSha256(append([]byte{0x00,0x14}, hash160...)); err != nil {
		return "", err
	}

	buf := append([]byte{mapNet[netType]}, hash160...)
	checksum := common.Sha256AfterSha256(buf)
	buf = append(buf, checksum[:4]...)
	return base58.Encode(buf),nil
}
