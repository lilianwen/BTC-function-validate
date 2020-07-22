package tx

import (
	"encoding/binary"
	"errors"
	"generateAddress/utils"
)

//todo:这种字段值是固定的代码怎么写更优雅？
type ScriptPubKeyP2PKH struct {
	OP_DUP byte
	OP_HASH160 byte
	PUSHDATA byte
	PubKeyHash [20]byte
	OP_EQUALVERIFY byte
	OP_CHECKSIG byte
}

func (spk *ScriptPubKeyP2PKH)Parse(raw string) error {
	var (
		err error
		startIndex  = int(0)
		endIndex = int(0)
	)
	if spk.OP_DUP,err  = utils.String2Byte(raw[startIndex:]);err !=nil {
		return err
	}

	startIndex += binary.Size(spk.OP_DUP)*2
	if spk.OP_HASH160,err  = utils.String2Byte(raw[startIndex:]);err !=nil {
		return err
	}

	startIndex += binary.Size(spk.OP_HASH160)*2
	if spk.PUSHDATA,err  = utils.String2Byte(raw[startIndex:]);err !=nil {
		return err
	}

	startIndex += binary.Size(spk.PUSHDATA)*2
	endIndex = startIndex + int(spk.PUSHDATA) * 2
	var pkhash []byte
	if pkhash,err  = utils.String2Bytes(raw[startIndex:endIndex]);err !=nil {
		return err
	}
	copy(spk.PubKeyHash[:], pkhash)

	startIndex = endIndex
	if spk.OP_EQUALVERIFY,err  = utils.String2Byte(raw[startIndex:]);err !=nil {
		return err
	}

	startIndex += binary.Size(spk.OP_EQUALVERIFY)*2
	if spk.OP_CHECKSIG,err  = utils.String2Byte(raw[startIndex:]);err !=nil {
		return err
	}

	if !spk.IsValid() {
		return errors.New("有非法数据")
	}

	return nil
}

func (spk *ScriptPubKeyP2PKH)IsValid() bool {
	if spk.OP_DUP == 0x76 &&
		spk.OP_HASH160 == 0xa9 &&
		spk.PUSHDATA == 0x14 &&
		spk.OP_EQUALVERIFY == 0x88 &&
		spk.OP_CHECKSIG == 0xac &&
		len(spk.PubKeyHash) == int(spk.PUSHDATA) {
		return true
	}
	return false
}

func (spk *ScriptPubKeyP2PKH)Serialize() []byte {
	var data []byte
	data = append(data, spk.OP_DUP)
	data = append(data, spk.OP_HASH160)
	data = append(data, spk.PUSHDATA)
	data = append(data, spk.PubKeyHash[:]...)
	data = append(data, spk.OP_EQUALVERIFY)
	data = append(data, spk.OP_CHECKSIG)
	return data
}

func NewScriptPubKeyP2PKH(pubKeyHash []byte) *ScriptPubKeyP2PKH {
	var spk = ScriptPubKeyP2PKH{}
	spk.OP_DUP  = 0x76
	spk.OP_HASH160  = 0xa9
	spk.PUSHDATA  = 0x14
	copy(spk.PubKeyHash[:], pubKeyHash)
	spk.OP_EQUALVERIFY = 0x88
	spk.OP_CHECKSIG = 0xac

	return &spk
}
