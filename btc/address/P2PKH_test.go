package address

import (
	"encoding/hex"
	"testing"
)

func TestNewP2PKH(t *testing.T) {
	t.Run("test compressed public key to address", func(t *testing.T) {
		var testcases = []struct{
			originalPrivKey string
			netType string
			address string
		} {
			{
				"a4f228d49910e8ecb53ba6f23f33fbfd2bad442e902ea20b8cf89c473237bf9f",
				"main",
				"127NVqnjf8gB9BFAW2dnQeM6wqmy1gbGtv",
			},
		}
		var err error
		var address string

		for _, oneCase := range testcases {
			privKey,_ := hex.DecodeString(oneCase.originalPrivKey)
			if address,err = NewP2PKH(privKey, oneCase.netType, true);err != nil {
				t.Error(err)
				return
			}
			if address != oneCase.address {
				t.Error("genereate compressed address error")
				t.Error("want: ", oneCase.address)
				t.Error("got:  ", address)
				return
			}
		}
	})
}
