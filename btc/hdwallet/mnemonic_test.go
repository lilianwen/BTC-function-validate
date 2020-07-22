package hdwallet

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func TestEntropy2Mnemonics(t *testing.T) {
	t.Run("test use entropy to generate mnemonic words", func(t *testing.T) {
		var words []string
		var err error
		var randDigit []byte
		if randDigit,err = hex.DecodeString("5e91c0b063824bc984073120461d4fa3"); err != nil {
			t.Error(err)
			return
		}
		if words, err = entropy2Mnemonics(new(big.Int).SetBytes(randDigit),4); err!= nil {
			t.Error(err)
			return
		}
		want := strings.Split("future mix clown shove caution tooth avoid tower cake couch fault elder", " ")
		if !reflect.DeepEqual(want, words) {
			t.Error("generate mnemonic words error")
			t.Error("want: ",want)
			t.Error("got: ", words)
			return
		}
	})
}

func TestMnemonics2Entropy(t *testing.T) {
	t.Run("test parse mnemonic words to seed", func(t *testing.T) {
		mnemonicWrods := "future mix clown shove caution tooth avoid tower cake couch fault elder"
		var (
			seed string
			err error
		)
		if seed, err = Mnemonics2Entropy(mnemonicWrods);err != nil {
			t.Error(err)
			return
		}
		want := "5e91c0b063824bc984073120461d4fa3"
		if seed != want {
			t.Error("error seed")
			t.Error("want:", want)
			t.Error("got:", seed)
		}
	})
}