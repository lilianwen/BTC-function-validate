package tx

import (
	"encoding/hex"
	"testing"
)

func TestOutPut_Parse(t *testing.T) {
	outputInRaw := "4baf2100000000001976a914db4d1141d0048b1ed15839d0b7a4c488cd368b0e88ac00000000"
	var out = OutPut{}
	if err := out.Parse(outputInRaw);err!= nil {
		t.Error(err)
		return
	}

	//https://learnmeabitcoin.com/explorer/transaction/c1b4e695098210a31fe02abffe9005cffc051bbe86ff33e173155bcbdc5821e3
	if !(out.Value == 2207563 &&
		out.ScriptPubKeySize.Value == uint64(0x19) &&
		hex.EncodeToString(out.ScriptPubKey) == "76a914db4d1141d0048b1ed15839d0b7a4c488cd368b0e88ac") {
		t.Error("parse output string in raw wrong")
		t.Error(out.String())
		return
	}
}
