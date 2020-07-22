package tx


import (
	"encoding/binary"
	"errors"
	"generateAddress/utils"
)

//todo:有没有其他类型的签名？
type SignatureP2PKH struct{
	Sequence byte //等于0x30表示DER序列的开始
	LengthOfSig byte
	Integer1 byte //todo:这个字段不知道是什么意思
	LengthOfX byte
	X []byte
	Integer2 byte //todo:这个字段也不知道是什么意思
	LengthOfY byte
	Y []byte
}

func (sig *SignatureP2PKH)Len() byte {
	return sig.LengthOfSig + byte(2)
}

func (sig *SignatureP2PKH)Serialize() []byte {
	var data []byte
	data = append(data, sig.Sequence)
	data = append(data, sig.LengthOfSig)
	data = append(data, sig.Integer1)
	data = append(data, sig.LengthOfX)
	data = append(data, sig.X...)
	data = append(data, sig.Integer2)
	data = append(data, sig.LengthOfY)
	data = append(data, sig.Y...)
	return data
}

//传进来的r，s是已经处理过的数据，不需要根据头部进行再处理
func NewSignatureP2PKH(r []byte, s []byte) SignatureP2PKH {
	var sig = SignatureP2PKH {}
	sig.Sequence = 0x30
	sig.Integer1 = 2
	sig.X = append(sig.X, r...)
	//if r[len(r)-1] & 0x80 != 0 {
	//	sig.X = append(sig.X, r...)
	//} else {
	//	sig.X = append([]byte{0}, r...)
	//}
	sig.LengthOfX = byte(len(sig.X))
	sig.Integer2 = 2
	sig.Y = append(sig.Y, s...)
	//if r[len(s)-1] & 0x80 != 0 {
	//	sig.Y = append(sig.Y, s...)
	//} else {
	//	sig.Y = append([]byte{0}, s...)
	//}
	sig.LengthOfY = byte(len(sig.Y))
	sig.LengthOfSig = byte(4 + sig.LengthOfX + sig.LengthOfY)
	return sig
}

type ScriptSigP2PKH struct{
	DataToPush1 byte //第一次要push到栈顶的数据长度
	Signature SignatureP2PKH //签名数据
	SigTxOp byte //签名交易的操作码
	DataToPush2 byte //第二次要push到栈顶的数据长度
	TypeOfPubKey byte //压缩公钥的前缀，0x02表示公钥的Y值为偶数，0x03表示公钥的Y值为奇数
	PubKeyX [32]byte//公钥的X坐标
}

func (ssig *ScriptSigP2PKH)Serialize() []byte {
	var data []byte
	var buf []byte
	data = append(data, ssig.DataToPush1)
	buf = ssig.Signature.Serialize()
	data = append(data, buf...)
	data = append(data, ssig.SigTxOp)
	data = append(data, ssig.DataToPush2)
	data = append(data, ssig.TypeOfPubKey)
	data = append(data, ssig.PubKeyX[:]...)

	return data
}

func NewScriptSigP2PKH(r, s []byte, compressedPubKey []byte) ScriptSigP2PKH {
	var ss =  ScriptSigP2PKH{}
	ss.Signature = NewSignatureP2PKH(r, s)
	ss.SigTxOp = byte(0x01)
	ss.DataToPush2 = byte(0x21)
	ss.TypeOfPubKey = compressedPubKey[0]
	copy(ss.PubKeyX[:], compressedPubKey[1:])
	ss.DataToPush1 = ss.Signature.Len() + 1 //需要再加上后面的SIGHASH_ALL
	return ss
}

// 判断该签名脚本是不是合法有效的P2PKH格式, unfinished
func (ss *ScriptSigP2PKH)IsValid(raw string) bool {
	if ss.DataToPush1 >= 1 && ss.DataToPush1 <= 0x4b &&
		ss.Signature.Sequence == 0x30 {
		return true
	}
	return false
}

//todo: 有没有规定最少字节？这样就可以不用写太多检查语句了
//现在暂时在最后一个字段进行长度检查
func (ss *ScriptSigP2PKH)Parse(raw string)  error {
	var (
		err error
		startIndex  = int(0)
		endIndex = int(0)
	)
	if ss.DataToPush1,err  = utils.String2Byte(raw[startIndex:]);err !=nil {
		return err
	}

	startIndex += binary.Size(ss.DataToPush1)*2
	if ss.Signature.Sequence,err = utils.String2Byte(raw[startIndex:]);err != nil {
		return err
	}

	startIndex += binary.Size(ss.Signature.Sequence)*2
	if ss.Signature.LengthOfSig,err = utils.String2Byte(raw[startIndex:]);err != nil {
		return err
	}

	startIndex += binary.Size(ss.Signature.LengthOfSig)*2
	if ss.Signature.Integer1,err = utils.String2Byte(raw[startIndex:]);err != nil {
		return err
	}

	startIndex += binary.Size(ss.Signature.Integer1)*2
	if ss.Signature.LengthOfX,err = utils.String2Byte(raw[startIndex:]);err != nil {
		return err
	}


	startIndex += binary.Size(ss.Signature.LengthOfX)*2
	endIndex = startIndex + int(ss.Signature.LengthOfX)*2
	if ss.Signature.X,err = utils.String2Bytes(raw[startIndex:endIndex]);err != nil {
		return err
	}

	startIndex = endIndex
	if ss.Signature.Integer2,err = utils.String2Byte(raw[startIndex:]);err != nil {
		return err
	}

	startIndex += binary.Size(ss.Signature.Integer2)*2
	if ss.Signature.LengthOfY,err = utils.String2Byte(raw[startIndex:]);err != nil {
		return err
	}

	startIndex += binary.Size(ss.Signature.LengthOfY)*2
	endIndex = startIndex + int(ss.Signature.LengthOfY)*2
	if ss.Signature.Y,err = utils.String2Bytes(raw[startIndex:endIndex]);err != nil {
		return err
	}

	startIndex = endIndex
	if ss.SigTxOp,err = utils.String2Byte(raw[startIndex:]);err != nil {
		return err
	}

	startIndex += binary.Size(ss.SigTxOp)*2
	if ss.DataToPush2,err = utils.String2Byte(raw[startIndex:]);err != nil {
		return err
	}

	startIndex += binary.Size(ss.DataToPush2)*2
	if ss.TypeOfPubKey,err = utils.String2Byte(raw[startIndex:]);err != nil {
		return err
	}

	startIndex += binary.Size(ss.TypeOfPubKey)*2
	endIndex = startIndex + 32*2
	if endIndex < len(raw)-1 {
		return errors.New("not enough data for public key X")
	} else if endIndex < len(raw)-1 {
		return errors.New("too many data for public key X")
	}
	var pubKeyX []byte
	if pubKeyX,err = utils.String2Bytes(raw[startIndex:endIndex]);err != nil {
		return err
	}
	copy(ss.PubKeyX[:], pubKeyX)

	return nil
}



