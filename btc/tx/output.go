package tx


import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"generateAddress/utils"
	"strconv"
)

type OutPut struct {
	Value uint64
	ScriptPubKeySize VarInt
	ScriptPubKey []byte
}

func (out *OutPut)String() string {
	str := "\nvalue:" + strconv.FormatInt(int64(out.Value), 10) +"\n"
	str = str + "scriptPubKeySize:" + strconv.FormatInt(int64(out.ScriptPubKeySize.Value), 10) + "\n"
	str = str + "scriptPubKey:" + hex.EncodeToString(out.ScriptPubKey) + "\n"

	return str
}

func (out *OutPut)Len() uint64 {
	return uint64(8 + out.ScriptPubKeySize.Len()+len(out.ScriptPubKey))
}

func (out *OutPut)Parse(outputInRaw string) error {
	//参数校验
	if len(outputInRaw) < 10*2 {
		return errors.New("output string is too short")
	}
	var (
		err error
		tmp []byte
		scriptPubKeyStart uint64
		scrptPubKeyEnd uint64
	)

	if tmp, err = utils.ReverseBigEdianString(outputInRaw[:16]);err != nil {
		return err
	}
	out.Value = binary.BigEndian.Uint64(tmp)

	if err = out.ScriptPubKeySize.Parse(outputInRaw[16:]);err != nil {
		return err
	}

	scriptPubKeyStart = uint64(16 + out.ScriptPubKeySize.Len()*2)
	scrptPubKeyEnd = scriptPubKeyStart + out.ScriptPubKeySize.Value*2//因为一个字节占两个十六进制字符
	if out.ScriptPubKey, err = hex.DecodeString(outputInRaw[scriptPubKeyStart:scrptPubKeyEnd]); err != nil {
		return err
	}

	return nil
}

func NewOutput (value uint64, pubKeyHash []byte) OutPut {
	var output = OutPut{}
	output.Value = value
	buf := NewScriptPubKeyP2PKH(pubKeyHash).Serialize()
	output.ScriptPubKey = append( output.ScriptPubKey, buf...)
	output.ScriptPubKeySize = NewVarInt(uint64(len(output.ScriptPubKey)))
	return output
}

func (out *OutPut)Serialize() []byte {
	var buf [8]byte
	var data []byte
	binary.LittleEndian.PutUint64(buf[:], out.Value)
	data = append(data, buf[:]...)
	data = append(data, out.ScriptPubKeySize.Data...)
	data = append(data, out.ScriptPubKey...)
	return data
}

