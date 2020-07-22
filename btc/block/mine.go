package block

import (
	"errors"
	"math"
	"math/big"
	"paper/common"
)

func Mine(header *Header, startNonce uint32) (uint32, error) {
	for i:=startNonce; true; i++ {
		header.Nonce = i
		buf := header.Serialize()
		blockHash := common.Sha256AfterSha256(buf)

		target := Bits2Target(header.Bits)
		common.ReverseBytes(blockHash[:])//注意：这里一定要反转一下顺序,因为big.Int是大端存储
		gotHash := new(big.Int).SetBytes(blockHash[:])
		if target.Cmp(gotHash) >= 0 { //bingo 挖到区块了
			return i,nil
		}
		//fmt.Println(i)
		if i == math.MaxUint32 {
			break
		}
	}
	return 0,errors.New("nonce not found")
}
