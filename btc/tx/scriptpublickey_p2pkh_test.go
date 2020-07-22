package tx


import (
	"paper/btc/address"
	"testing"
)



//https://blockchain.info/rawtx/c8bc7cff08249ea5f9970e15be64259b0135b0b6e37f1f9f088a719508cbd8bc
//https://blockchain.info/rawtx/ba67adc8a8aeb44cbd59bfe207ed6245a409ab5ea7b0b667baf28c5f7271c039
func TestScriptPubKeyP2PKH_Parse(t *testing.T) {
	var testcases = []struct{
		raw string
		addr string
	} {
		{
			"76a9147232ca33e0797405a512fa872934cd922c81296588ac",
			"1BQpsoxUq7N5Hv57QCnzLBbZSHGtqafaFy",
		},
		{
			"76a9146fcfb1bdeb4d3d36705b5e5ab4357c9176be761988ac",
			"1BCCp9VZYvzuR1t1xL7CS9ajo3os1kxsPe",
		},
		{
			"76a91446609ac55f494f1d46474b31480bac25006f1a9088ac",
			"17R82ddkebVTMmiKgXn4HNp2scqDA1jtzq",
		},
	}

	var scriptPubKey = ScriptPubKeyP2PKH{}
	for _,oneCase := range testcases {
		if err := scriptPubKey.Parse(oneCase.raw);err != nil {
			t.Error(err)
			return
		}
		got := address.MustPubKeyHash2Address(scriptPubKey.PubKeyHash[:], "p2pkh")
		if  got != oneCase.addr {
			t.Error("wrong public key hash")
			t.Error("want:", oneCase.addr)
			t.Error("got: ", got)
			return
		}
	}
}
