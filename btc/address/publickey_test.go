package address

import (
	"encoding/hex"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"testing"
)

func TestNewUncompressPubKey(t *testing.T) {
	var testcases = []struct{
		originalPrivKey string
		compressedPubKey string
	} {
		{
			"5a2d2535d6f40cb64bc76c33551b2a1d7b4c5222893d2dc93590c55128f788b2",
			"02e92a351210716373fc214b8320c04a50e35f64eba23b92a812c8e52777ae79c5",
		},
	}

	for _,oneCase := range testcases {
		privKeyInBytes, _ := hex.DecodeString(oneCase.originalPrivKey)
		privKey := secp256k1.PrivKeyFromBytes(privKeyInBytes)
		compressedPubKey := NewCompressPubKey(privKey.PubKey().X().Bytes(), privKey.PubKey().Y().Bytes())

		if compressedPubKey != oneCase.compressedPubKey {
			t.Error("compressed public key error")
			t.Error("want: ", oneCase.compressedPubKey)
			t.Error("got:  ", compressedPubKey)
		}
	}
}

func TestNewCompressPubKey(t *testing.T) {
	var testcases = []struct{
		originalPrivKey string
		uncompressedPubKey string
	} {
		{
			"5a2d2535d6f40cb64bc76c33551b2a1d7b4c5222893d2dc93590c55128f788b2",
			"04e92a351210716373fc214b8320c04a50e35f64eba23b92a812c8e52777ae79c53cc2bec2369a33918f2ae6680ef0ff03056cae8849466556959c8784b07fdc0a",
		},
	}

	for _,oneCase := range testcases {
		privKeyInBytes, _ := hex.DecodeString(oneCase.originalPrivKey)
		privKey := secp256k1.PrivKeyFromBytes(privKeyInBytes)
		uncompressedPubKey := NewUncompressPubKey(privKey.PubKey().X().Bytes(), privKey.PubKey().Y().Bytes())

		if uncompressedPubKey != oneCase.uncompressedPubKey {
			t.Error("uncompressed public key error")
			t.Error("want: ", oneCase.uncompressedPubKey)
			t.Error("got:  ", uncompressedPubKey)
		}
	}
}

