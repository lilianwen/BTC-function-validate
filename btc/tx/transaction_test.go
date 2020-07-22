package tx

import (
	"encoding/hex"
	"generateAddress/utils"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"paper/btc/address"
	"paper/common"
	"testing"
)

func TestTransaction_Parse(t *testing.T) {
	t.SkipNow()
	//txStr := "01000000017967a5185e907a25225574544c31f7b059c1a191d65b53dcc1554d339c4f9efc010000006a47304402206a2eb16b7b92051d0fa38c133e67684ed064effada1d7f925c842da401d4f22702201f196b10e6e4b4a9fff948e5c5d71ec5da53e90529c8dbd122bff2b1d21dc8a90121039b7bcd0824b9a9164f7ba098408e63e5b7e3cf90835cceb19868f54f8961a825ffffffff014baf2100000000001976a914db4d1141d0048b1ed15839d0b7a4c488cd368b0e88ac00000000"
	//txStr := "02000000014b228cc685d10166d213c5b4470a9d97404b690edd3f6f21abaed3e23c107cdd000000006a4730440220496f8122194bcf88914a67f38d41fad4c83dd59fc1710bdec67858722800d8f0022019427ec2671ce40c67b31c36ef0572c1d69fc05f7cfc04c21f9b65be8cc618d5012103140f5d162fe4d884deb33bfb62980d2460c1d3d2512cd83cd96561329fa05324fdffffff0240420f00000000001976a9140da6e64d32928864edbe4c96364108beab6d36b988acdee92101000000001976a914b1177823769ef9c845b1e32cf53b4e60d077347088acd3a31a00"
	txStr := "0100000002a6d9cb3fc5328b372695d64236a136a5aec3a333b3059e7f9d88cd5ec3c0e0ee01000000dc0048304502210080075aa29c42f8062f75cf6ab32004944417af974775581719008052c78719710220409fee54c6ddf2ca83e090077e443f95b427a63cc1ad87fca2625951b789d1c201493046022100b61d8f206d17efd6db32dad106f754f231ee8a16882929b1eb39a58bfd36b39e022100c62cff92dd6fb22b373025fc9b87044cf1b33502acc9de707e5f54d1c8a042a7014752210293baf0397588acc1aba056e868fd188dc0eea7554b45370aae862f9d2493a4c121020ab7517cf22a46b503ee8dcae7f9f109ec4cd19f0ab9d77c89c607554f3d5aa952aeffffffff3040c42258489d633033906125dc9999a8b0fadebde325db13c7fa6a0126f1b30e0100006b48304502203fe5f04a013512a4773414b25edc8c7915473dd5cf87bc73d28e1aaffdb4d14f022100e16156d526d1498f2cf5eb02d53e02f7fd5cf1dfdd25e4b032fdc5c59c9fd27b01210203635e5c184951e14fcfecc83b15960594f4fceec729e09a4a517b0a03a7f4b9ffffffff0240420f00000000001976a9147232ca33e0797405a512fa872934cd922c81296588ac671ab5220000000017a914622854939d571b63df97f47e8302b700ab2932b68700000000"
	tx := Transaction{}

	if err := tx.Parse(txStr); err != nil {
		t.Error("parse transaction wrong")
		t.Error()
		return
	}
	tx.Print()
}

func TestConstructTransaction(t *testing.T) {
	t.SkipNow()
	var testcases = []struct {
		privKey string
		toAddr string
		amount uint64
		fee uint64
		changeAddr string
		want string
	} {
		{
			"cUMnvHo9Tw6CyNizQnp4TgGnBmxELWeX2VKK6ER1PNV1gnssnGdE",
			"mrqixX2nnvWViAF2JXAzxJTq9XutCM4KsS",
			1000000,
			339,
			"mwfL1gZfZ2TxgJzrQwvpkvNiTxgtG6qcPp",
			"0200000001560c1e8a7e110fb846269769c581d9dca5c2c2454369220ca77c87ae568d43f3010000006b4830450221009e0f8bba6ae85c57f7fa53900524141f92b3d0e15ecd46c3f6321a0d3e53c9e8022068525d4bfd26901274ed55f85fdb99e509a3cfab6b0764d31e7d21b2f519e04a012103140f5d162fe4d884deb33bfb62980d2460c1d3d2512cd83cd96561329fa05324ffffffff0240420f00000000001976a9147c362764ba28f48888b9c9b706d2de8fdb4abe1888ac74ca6a00000000001976a914b1177823769ef9c845b1e32cf53b4e60d077347088ac00000000",
		},
	}

	for _, oneCase := range testcases {
		privKey := secp256k1.PrivKeyFromBytes(address.DecodeWIF(oneCase.privKey))
		var tx []byte
		var err error
		if tx, err = ConstructTransaction(privKey,
			oneCase.toAddr,
			oneCase.amount,
			oneCase.fee,
			oneCase.changeAddr); err != nil {
			t.Error(err)
			return
		}

		txid := common.Sha256AfterSha256(tx)
		t.Log("txid: ", hex.EncodeToString(utils.ReverseBytes(txid[:])))
		got := hex.EncodeToString(tx)
		t.Log("signed trasaction:",got)
		//通不过测试是对的，因为签名数据没办法判断对错，只有通过节点广播出去，被其他节点验证接受才算成功
		//这里只是打印一下结果。然后把这个结果通过Electrum钱包广播出去才能验证是否正确
		if got != oneCase.want {
			t.Error("sign transaction error")
			t.Error("want:", oneCase.want)
			t.Error("got: ", got)
			return
		}
	}
}

func TestTxHash(t *testing.T) {
	var signedTx = "0200000001560c1e8a7e110fb846269769c581d9dca5c2c2454369220ca77c87ae568d43f3010000006b4830450221009e0f8bba6ae85c57f7fa53900524141f92b3d0e15ecd46c3f6321a0d3e53c9e8022068525d4bfd26901274ed55f85fdb99e509a3cfab6b0764d31e7d21b2f519e04a012103140f5d162fe4d884deb33bfb62980d2460c1d3d2512cd83cd96561329fa05324ffffffff0240420f00000000001976a9147c362764ba28f48888b9c9b706d2de8fdb4abe1888ac74ca6a00000000001976a914b1177823769ef9c845b1e32cf53b4e60d077347088ac00000000"
	var want = "d81adc652a42e0bdfe1331299570897fde4f0ebebc22a2e2f634e5338d0083d0"
	buf, err := hex.DecodeString(signedTx)
	if err != nil {
		t.Error(err)
		return
	}
	txid := common.Sha256AfterSha256(buf)
	common.ReverseBytes(txid[:]) //注意，以字符串显示的时候需要把数据顺序反过来。
	if got := hex.EncodeToString(txid[:]); got != want {
		t.Error("calculate tx hash failed")
		t.Error("want: ", want)
		t.Error("got:  ", got)
		return
	}
}
