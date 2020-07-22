package hdwallet

import (
	"encoding/binary"
	"errors"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"math/big"
	"paper/common"
	"strconv"
	"strings"
)

const (
	masterKey = "Bitcoin seed"//todo:这个是不是规定死了必须是这个？还得仔细看文档
)

func pathElem2Num(path string) (uint32, error) {
	var (
		base = uint32(0)
		strNum = path
		num int
		err error
	)

	if len(path) >= 1 && path[len(path)-1:] == "'" {
		base = uint32(0x80000000)
		strNum = path[:len(path)-1]
	}
	if num, err = strconv.Atoi(strNum); err != nil {
		return uint32(0),err
	}
	return base + uint32(num),nil
}

//string of hierarchical path convert to numbers
func hPath2Nums(path string) ([]uint32, error) {
	var (
		elems []string
		err error
		n uint32
		nums []uint32
	)
	if elems = strings.Split(path, "/"); len(elems) != 6 {
		return nil,errors.New("invalid path")
	}
	//pieces[0] is "m"
	var pathElems = []struct {
		name string
		value string
	}{
		{"purpose", elems[1]},
		{"coinType",elems[2]},
		{"change", elems[3]},
		{"account", elems[4]},
		{"index", elems[5]},
	}

	for _, elem := range pathElems {
		if n, err = pathElem2Num(elem.value); err != nil {
			return nil,errors.New("invalid " + elem.name)
		}
		nums = append(nums, n)
	}
	return nums,nil
}

//用助记词和派生路径生成子私钥
func DerivateChildPrivKeyFromMnemonic(mnemonicWrods , path , passphase string) (*secp256k1.PrivateKey, error) {
	//参数校验
	var (
		err error
		rootSeed []byte
		nums []uint32
	)

	if nums, err = hPath2Nums(path); err != nil {
		return nil, err
	}

	//把助记词转换成rootSeed
	if rootSeed, err = Mnemonics2RootSeed(mnemonicWrods, passphase);err != nil {
		return nil, err
	}

	return masterDerivateChildPrivKeyImpl(rootSeed, nums)
}

func masterDerivateChildPrivKeyImpl(rootSeed []byte, path []uint32) (*secp256k1.PrivateKey, error){
	var (
		masterExtendedPrivKey []byte
		parentPrivKey *secp256k1.PrivateKey
		parentChainCode []byte
		childPrivKey *secp256k1.PrivateKey
		childChainCode []byte
		err error
		//strMasterExtendPrivKey string
	)

	//用rootseed算出masterExtendedPrivKey
	masterExtendedPrivKey = common.HMACWithSHA512(rootSeed, []byte(masterKey))//重要：这里就是用rootKey
	parentPrivKey = secp256k1.PrivKeyFromBytes(masterExtendedPrivKey[:32])
	parentChainCode = masterExtendedPrivKey[32:]

	//strMasterExtendPrivKey = EncodeExtendKey(uint32(0x0488ADE4), 0, 0,0,
	//	parentChainCode, append([]byte{0}, parentPrivKey.Serialize()...))
	//fmt.Println("master extended private key: ", strMasterExtendPrivKey)

	//var fingerPrint uint32
	for i, elem := range path {
		if childPrivKey, childChainCode, err = DerivateChildPrivKeyFromParentPrivKey(parentPrivKey, parentChainCode, elem); err != nil {
			return nil, err
		}
		if i == 3 {//把account extended private key打印出来，可以导入Electrum钱包里去
			//if fingerPrint, err = generateFingerprint(parentPrivKey); err != nil {
			//	return nil,err
			//}
			//accountExtendedPrivKey := EncodeExtendKey(uint32(0x0488ADE4), byte(i+1), fingerPrint, elem, parentChainCode,
			//	append([]byte{0}, parentPrivKey.Serialize()...))
			//fmt.Println("account extended private key:", accountExtendedPrivKey)
		}
		parentPrivKey = childPrivKey
		parentChainCode = childChainCode
	}

	return childPrivKey,nil
}

// 用父私钥派生出子私钥
func DerivateChildPrivKeyFromParentPrivKey(parentPrivKey *secp256k1.PrivateKey, parentChainCode []byte, childIndex uint32) (*secp256k1.PrivateKey, []byte, error) {
	var (
		childExtendedKey []byte
		childPrivKey *big.Int
		data []byte
	)

	if childIndex >= uint32(1<<31) {
		privKK := parentPrivKey.Key.Bytes()
		data = append([]byte{0x00}, privKK[:]...)
		data = append(data, common.Uint32ToBytes(childIndex)...)
	} else {
		data = append(parentPrivKey.PubKey().SerializeCompressed(), common.Uint32ToBytes(childIndex)...)
	}

	childExtendedKey = common.HMACWithSHA512(data, parentChainCode)

	n := secp256k1.Params().N
	parse256il :=new(big.Int).SetBytes(secp256k1.PrivKeyFromBytes(childExtendedKey[:32]).Serialize())
	if parse256il.Cmp(n) >= 0 {
		return nil,nil,errors.New("invalid child private key")
	}

	parse256il.Add(parse256il, new(big.Int).SetBytes(parentPrivKey.Serialize()))
	childPrivKey = parse256il.Mod(parse256il, n)
	if childPrivKey.Cmp(big.NewInt(0)) == 0 {
		return nil,nil,errors.New("invalid child private key")
	}

	return secp256k1.PrivKeyFromBytes(childPrivKey.Bytes()),childExtendedKey[32:],nil
}

func generateFingerprint(privKey *secp256k1.PrivateKey) (uint32, error){
	var (
		hash160 []byte
		err error
	)
	if hash160, err = common.Ripemd160AfterSha256(privKey.PubKey().SerializeCompressed()); err != nil {
		return uint32(0), err
	}

	return binary.BigEndian.Uint32(hash160[:4]),nil
}

func EncodeExtendKey(chainType uint32, depth byte, parentFingerprint uint32,childNum uint32, chainCode []byte, keyData []byte) string{
	/*
		https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Extended_keys
		Extended public and private keys are serialized as follows:

		4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
		1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
		4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
		4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
		32 bytes: the chain code
		33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
		This 78 byte structure can be encoded like other Bitcoin data in Base58, by first adding 32 checksum bits
		(derived from the double SHA-256 checksum), and then converting to the Base58 representation. This results in a
		Base58-encoded string of up to 112 characters. Because of the choice of the version bytes, the Base58 representation
		will start with "xprv" or "xpub" on mainnet, "tprv" or "tpub" on testnet.
	*/
	var extendedData []byte
	extendedData = append(extendedData, common.Uint32ToBytes(chainType)...)
	extendedData = append(extendedData, depth)
	extendedData = append(extendedData, common.Uint32ToBytes(parentFingerprint)...)
	extendedData = append(extendedData, common.Uint32ToBytes(childNum)...)
	extendedData = append(extendedData, chainCode...)
	extendedData = append(extendedData, keyData...)
	checksum := common.Sha256AfterSha256(extendedData)
	extendedData = append(extendedData,checksum[:4]...)

	return base58.Encode(extendedData)
}