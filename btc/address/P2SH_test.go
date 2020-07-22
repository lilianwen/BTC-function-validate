package address

import (
	"encoding/hex"
	"testing"
)

func TestNewP2SH(t *testing.T) {
	var testcases = []struct{
		originalPrivKey string
		netType string
		address string
	} {
		//{
		//	"4c93230bf458fa8211c3a6504401b7b171014843a96fd08fb192da558ba30261",
		//	"main",
		//	"36GGo8iS7dQtSJvdebLX7oGyFTDmD6DyrL",
		//},
		//{
		//	"ccea9c5a20e2b78c2e0fbdd8ae2d2b67e6b1894ccb7a55fc1de08bd53994ea64 ",
		//	"main",
		//	"3B8gkwUd1ZhpGKqedix8y16zysN6QWqQxS",
		//},
		//{
		//	"a12618ff6540dcd79bf68fda2faf0589b672e18b99a1ebcc32a40a67acdab608",
		//	"main",
		//	"3ErPbBU5rzPwtvNfCZip3pMEVopnPrKq3N",
		//},
		{"cff0fbaaae8f6ee6ebb35f98afa4036958d929ee18143b26c466251cd966b128",
			"main",
			"3QehmGVcZsJEVc1uPSvXwamRQn56JR7qKd",
		},
	}
	var err error
	var address string
	for _, oneCase := range testcases {
		privKey,_ := hex.DecodeString(oneCase.originalPrivKey)
		//fmt.Println(NewPrivKeyInWIF(privKey, true))
		if address,err = NewP2SH(privKey, oneCase.netType,true);err != nil {
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
}
