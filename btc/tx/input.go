package tx

import (
"encoding/binary"
"encoding/hex"
"errors"
"fmt"
"generateAddress/utils"
"strconv"
)

type Input struct {
	TxID [32]byte
	VOUT uint32
	ScriptSigSize VarInt //可变长
	ScriptSig []byte
	Sequence uint32 //用于锁定时间或禁用（0xffffffff）
}

func (in *Input)Serialize() []byte {
	var data []byte
	var buf [4]byte
	data = append(data, in.TxID[:]...)

	binary.LittleEndian.PutUint32(buf[:], in.VOUT)
	data = append(data, buf[:]...)
	data = append(data, in.ScriptSigSize.Data...)
	data = append(data, in.ScriptSig...)
	binary.LittleEndian.PutUint32(buf[:], in.Sequence)
	data = append(data, buf[:]...)

	return data
}

//设计一个函数，把[]byte按照hex格式转换成字符串
func (in *Input)String() string {
	str := "TxID:" + hex.EncodeToString(in.TxID[:]) + "\n"
	str = str + "VOUT:" + strconv.Itoa(int(in.VOUT)) + "\n"
	str = str + "VarInt:" + hex.EncodeToString(in.ScriptSigSize.Data) + "\n"
	str = str + "ScriptSig:" + hex.EncodeToString(in.ScriptSig) + "\n"
	str = str + "Sequence:" + strconv.Itoa(int(in.Sequence)) + "\n"
	return str
}

//返回Input的长度，单位字节
func (in *Input)Len() uint64 {
	return uint64(32+4+in.ScriptSigSize.Len()+len(in.ScriptSig)+4)
}

func (in *Input)Parse(inputInRaw string) error {
	//参数校验
	if len(inputInRaw) < 42*2 {
		return errors.New("input raw string is too short")
	}
	var (
		err error
		tmp []byte
		scriptStart uint64
		scriptEnd uint64
	)

	//txid字符串是大端形式的，需要把它逆序才能和区块链浏览器里的数据一致
	if tmp,err = utils.ReverseBigEdianString(inputInRaw[:64]); err != nil {
		return err
	}
	copy(in.TxID[:], tmp)

	if tmp, err = hex.DecodeString(inputInRaw[64:72]);err != nil {
		return err
	}
	in.VOUT = binary.LittleEndian.Uint32(tmp)

	if err = in.ScriptSigSize.Parse(inputInRaw[72:]); err != nil {
		return err
	}

	scriptStart = uint64(72 + in.ScriptSigSize.Len()*2)
	scriptEnd = scriptStart + in.ScriptSigSize.Value*2//因为一个字节占两个十六进制字符串字符
	fmt.Println(inputInRaw[scriptStart:scriptEnd])
	if in.ScriptSig, err = hex.DecodeString(inputInRaw[scriptStart:scriptEnd]); err != nil {
		return err
	}

	if tmp,err = hex.DecodeString( inputInRaw[scriptEnd:scriptEnd+8] );err != nil {
		return err
	}
	in.Sequence = binary.LittleEndian.Uint32(tmp)

	return nil
}

