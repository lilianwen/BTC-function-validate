package tx


import (
	"encoding/binary"
	"encoding/hex"
	"generateAddress/utils"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrec/secp256k1/ecdsa"
	"paper/btc/address"
	"paper/common"
	"testing"
)

//数据来源，交易哈希c8bc7cff08249ea5f9970e15be64259b0135b0b6e37f1f9f088a719508cbd8bc
func TestScriptSigP2PKH_Parse(t *testing.T) {
	var testcases = []struct{
		raw string  //原始的ScriptSig段hex格式数据
		txRaw string //原始的交易hex格式数据
		preScriptPubKey string //要验签的input解锁的前pubkeyscript
		address string //ScriptSig包含的公钥对应的P2PKH地址
		inputIndex uint64 //要验签的input所在tx中的索引
	} {
		{
			"48304502203fe5f04a013512a4773414b25edc8c7915473dd5cf87bc73d28e1aaffdb4d14f022100e16156d526d1498f2cf5eb02d53e02f7fd5cf1dfdd25e4b032fdc5c59c9fd27b01210203635e5c184951e14fcfecc83b15960594f4fceec729e09a4a517b0a03a7f4b9",
			"0100000002a6d9cb3fc5328b372695d64236a136a5aec3a333b3059e7f9d88cd5ec3c0e0ee01000000dc0048304502210080075aa29c42f8062f75cf6ab32004944417af974775581719008052c78719710220409fee54c6ddf2ca83e090077e443f95b427a63cc1ad87fca2625951b789d1c201493046022100b61d8f206d17efd6db32dad106f754f231ee8a16882929b1eb39a58bfd36b39e022100c62cff92dd6fb22b373025fc9b87044cf1b33502acc9de707e5f54d1c8a042a7014752210293baf0397588acc1aba056e868fd188dc0eea7554b45370aae862f9d2493a4c121020ab7517cf22a46b503ee8dcae7f9f109ec4cd19f0ab9d77c89c607554f3d5aa952aeffffffff3040c42258489d633033906125dc9999a8b0fadebde325db13c7fa6a0126f1b30e0100006b48304502203fe5f04a013512a4773414b25edc8c7915473dd5cf87bc73d28e1aaffdb4d14f022100e16156d526d1498f2cf5eb02d53e02f7fd5cf1dfdd25e4b032fdc5c59c9fd27b01210203635e5c184951e14fcfecc83b15960594f4fceec729e09a4a517b0a03a7f4b9ffffffff0240420f00000000001976a9147232ca33e0797405a512fa872934cd922c81296588ac671ab5220000000017a914622854939d571b63df97f47e8302b700ab2932b68700000000",
			"76a91444524fa542897f46a9a0cccc27ccb91ba822b4b688ac",
			"17EFZ829NBT2WETLj3wJ5YUfXVaGckuUgs",
			1,
		},
	}

	var scriptSigp2pkh = ScriptSigP2PKH{}
	var err error
	for _,oneCase := range testcases {
		if err = scriptSigp2pkh.Parse(oneCase.raw); err != nil {
			t.Error(err)
			return
		}
		//计算压缩公钥
		compressedPubKey := append([]byte{scriptSigp2pkh.TypeOfPubKey}, scriptSigp2pkh.PubKeyX[:]...)
		pubKeyHash, err := common.Ripemd160AfterSha256(compressedPubKey)
		if err != nil {
			t.Error(err)
			return
		}
		got := address.MustPubKeyHash2Address(pubKeyHash, "p2pkh")
		if got != oneCase.address {
			t.Error("wrong address")
			t.Error("want:", oneCase.address)
			t.Error("got: ", got)
		}

		//验证Input签名
		r := secp256k1.ModNScalar{}
		s := secp256k1.ModNScalar{}

		if scriptSigp2pkh.Signature.LengthOfX == 0x21 {
			if r.SetByteSlice(scriptSigp2pkh.Signature.X[1:]) {
				t.Error("signature r set bytes slice overflow")
				return
			}
		} else {
			if r.SetByteSlice(scriptSigp2pkh.Signature.X[:]) {
				t.Error("signature r set bytes slice overflow")
				return
			}
		}

		if scriptSigp2pkh.Signature.LengthOfY == 0x21 {
			if s.SetByteSlice(scriptSigp2pkh.Signature.Y[1:]) {
				t.Error("signature s set bytes slice overflow")
				return
			}
		} else {
			if s.SetByteSlice(scriptSigp2pkh.Signature.Y[:]) {
				t.Error("signature s set bytes slice overflow")
				return
			}
		}

		sig := ecdsa.NewSignature(&r, &s)

		//处理交易数据
		txData := Transaction{}
		if err=txData.Parse(oneCase.txRaw);err != nil {
			t.Error(err)
			return
		}
		//验证我们想要的那个input的签名
		var verifyData []byte
		var buf = make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, txData.Version)
		verifyData = append(verifyData, buf...)
		verifyData = append(verifyData, txData.InputCount.Data...)
		for i:=uint64(0); i< txData.InputCount.Value; i++ {
			verifyData = append(verifyData, utils.ReverseBytes(txData.Inputs[i].TxID[:])...)//大端小端
			var buf = make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, txData.Inputs[i].VOUT)
			verifyData = append(verifyData, buf...)

			if i == oneCase.inputIndex {
				preScriptSize := byte(len(oneCase.preScriptPubKey)/2)
				verifyData = append(verifyData, preScriptSize)

				//把ScriptSig替换成scriptPubKey
				if buf, err =hex.DecodeString(oneCase.preScriptPubKey);err != nil {
					t.Error(err)
					return
				}
				verifyData = append(verifyData, buf...)
			} else {
				//删除其他input的ScriptSig字段
				verifyData = append(verifyData, byte(0))//长度ScriptSig长度调整为0
			}

			binary.BigEndian.PutUint32(buf, txData.Inputs[i].Sequence)
			verifyData = append(verifyData, buf[:4]...)
		}

		verifyData = append(verifyData, txData.OutputCount.Data...)
		for i:=uint64(0); i< txData.OutputCount.Value; i++ {
			var buf = make([]byte, 8)
			binary.LittleEndian.PutUint64(buf, txData.OutPuts[i].Value)
			verifyData = append(verifyData,buf...)
			verifyData = append(verifyData, txData.OutPuts[i].ScriptPubKeySize.Data...)
			verifyData = append(verifyData, txData.OutPuts[i].ScriptPubKey...)
		}
		binary.BigEndian.PutUint32(buf, txData.Locktime)
		verifyData = append(verifyData, buf...)
		verifyData = append(verifyData, []byte{0x01,0x00,0x00,0x00}...)//加上小端序的SIGHASH_ALL
		//fmt.Println(hex.EncodeToString(verifyData))

		m:=common.Sha256AfterSha256(verifyData)
		//fmt.Println(hex.EncodeToString(m[:]))

		pubKey,err := secp256k1.ParsePubKey(compressedPubKey)
		if err != nil {
			t.Error(err)
			return
		}

		if !sig.Verify(m[:], pubKey) {
			t.Error("签名验证失败")
			return
		}
	}
}

