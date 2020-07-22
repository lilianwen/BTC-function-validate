package address

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestNewPrivKeyInWIF(t *testing.T) {
	var testcases = []struct{
		originalPrivKey string
		compressedPrivKey string
		uncompressedPrivKey string
	} {
		{
			"ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2",
			"L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6",
			"5Kdc3UAwGmHHuj6fQD1LDmKR6J3SwYyFWyHgxKAZ2cKRzVCRETY",
		},
		{
			"8A7FD53F196F0CCFDC977A1CD0A035ACE70741B6BDB3DE58D5C3C1BEA68A3798",
			"L1rwDKpBHj8Fi611t8P37B6DS8cpruhbvmXCjLn7zLNcBnSJCpKv",
			"5JsHMvCbWAYYszms3XDhMRwei3BPAwzEMLbwKCjPt42ixUWd4aa",
		},
	}

	for _,oneCase := range testcases {
		privKey, _ := hex.DecodeString(oneCase.originalPrivKey)
		compressedWIF := NewPrivKeyInWIF(privKey,true)
		uncompressedWIF := NewPrivKeyInWIF(privKey,false)

		if compressedWIF != oneCase.compressedPrivKey {
			t.Error("compressed private key error")
			t.Error("want: ", oneCase.compressedPrivKey)
			t.Error("got:  ", compressedWIF)
		}

		if uncompressedWIF != oneCase.uncompressedPrivKey {
			t.Error("compressed private key error")
			t.Error("want: ", oneCase.uncompressedPrivKey)
			t.Error("got:  ", uncompressedWIF)
		}
	}
}

func TestDecodeWIF(t *testing.T) {
	var testcases = []struct{
		wif string
		want string
	} {
		{
			"5Kdc3UAwGmHHuj6fQD1LDmKR6J3SwYyFWyHgxKAZ2cKRzVCRETY",
			"ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2",
		},
		{
			"L4BvQmJ2B5GcEBqbMaE1GdqvB6Rre4Av3vQfS5d5DQQ2XAAdeWdy",
			"cff0fbaaae8f6ee6ebb35f98afa4036958d929ee18143b26c466251cd966b128",
		},
	}

	for _,oneCase := range testcases {
		privKey := DecodeWIF(oneCase.wif)
		want,_ := hex.DecodeString(oneCase.want)

		if !reflect.DeepEqual(want, privKey) {
			t.Error("decode wif error")
			t.Error("want: ", oneCase.want)
			t.Error("got:  ", hex.EncodeToString(privKey))
		}
	}
}