package hdwallet

import (
	"github.com/decred/dcrd/dcrec/secp256k1"
	"paper/btc/address"
	"testing"
)

func TestDerivateChildPrivKeyFromMnemonic(t *testing.T) {
	var (
		childPrivKey *secp256k1.PrivateKey
		//mnemonic = "panic uphold view opera exit trouble access pet turkey lesson nut board burger visit raw"
		mnemonic = "refuse any female box bird silly broccoli change place plunge peanut fly"
		want = "KziSJGGrwuB3RuNdWPBDKYCCfW12vVBNz25hJ3rNsaoteiuRnYHp"
		err error
		got string
	)
	if childPrivKey, err = DerivateChildPrivKeyFromMnemonic(mnemonic, "m/44'/0'/0'/0/0", ""); err != nil {
		t.Error(err)
		return
	}


	if got = address.NewPrivKeyInWIF(childPrivKey.Serialize(), true); got != want {
		t.Error("got child private key error")
		t.Error("want:", want)
		t.Error("got: ", got)
		return
	}
}
