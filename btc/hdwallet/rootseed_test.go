package hdwallet

import (
	"encoding/hex"
	"testing"
)

func TestMnemonicWords2RootSeed(t *testing.T) {
	//t.SkipNow()
	t.Run("test use words to generate root seed", func(t *testing.T) {
		var (
			words = "glow laugh acquire menu anchor evil occur put hover renew calm purpose"
			seed []byte
			err error
			want = "afab97eb2f25d6c4cd3ca02674ab362a3c851a7c81b017a411345453ce869cb09ff8508d359a1091f0eb1b52c988fc686dcc21b2e57129a8036ea351808c2ee5"
			got string
		)

		if seed,err = Mnemonics2RootSeed(words, "TREZOR"); err != nil {
			t.Error(err)
			return
		}

		got = hex.EncodeToString(seed)
		if want != got {
			t.Error("error seed")
			t.Error("want:", want)
			t.Error("got:", got)
		}
	})
}
