package tx


import (
	"encoding/hex"
	"testing"
)

func TestInput_Parse(t *testing.T) {
	var inputInRaw = "7967a5185e907a25225574544c31f7b059c1a191d65b53dcc1554d339c4f9efc010000006a47304402206a2eb16b7b92051d0fa38c133e67684ed064effada1d7f925c842da401d4f22702201f196b10e6e4b4a9fff948e5c5d71ec5da53e90529c8dbd122bff2b1d21dc8a90121039b7bcd0824b9a9164f7ba098408e63e5b7e3cf90835cceb19868f54f8961a825ffffffff"
	//fmt.Println(len(inputInRaw))
	//return
	var input = Input{}
	if err := input.Parse(inputInRaw); err!=nil {
		t.Error(err)
		return
	}

	//https://chain.api.btc.com/v3/tx/c1b4e695098210a31fe02abffe9005cffc051bbe86ff33e173155bcbdc5821e3
	if !(hex.EncodeToString(input.TxID[:]) == "fc9e4f9c334d55c1dc535bd691a1c159b0f7314c54745522257a905e18a56779" &&
		input.VOUT == 1 &&
		input.ScriptSigSize.Value == uint64(0x6a) &&
		hex.EncodeToString(input.ScriptSig) == "47304402206a2eb16b7b92051d0fa38c133e67684ed064effada1d7f925c842da401d4f22702201f196b10e6e4b4a9fff948e5c5d71ec5da53e90529c8dbd122bff2b1d21dc8a90121039b7bcd0824b9a9164f7ba098408e63e5b7e3cf90835cceb19868f54f8961a825" &&
		input.Sequence == 4294967295 ) {
		t.Error("parse input error")
		t.Error(input.String())
		return
	}
}
