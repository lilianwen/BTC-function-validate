package tx

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"generateAddress/utils"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrec/secp256k1/ecdsa"
	"github.com/thedevsaddam/gojsonq"
	"io/ioutil"
	"net/http"
	"paper/btc/address"
	"paper/common"
)

type Transaction struct {
	Version uint32 //version of transaction data structure
	InputCount VarInt
	Inputs []Input
	OutputCount VarInt
	OutPuts []OutPut
	Locktime uint32
}

func (tx *Transaction)Print() {
	fmt.Println("version: ", tx.Version)
	fmt.Println("InputCount:", tx.InputCount.Value)
	for _,input := range tx.Inputs {
		fmt.Println(input.String())
	}
	fmt.Println("OutputCount:", tx.OutputCount.Value)
	for _,output := range tx.OutPuts {
		fmt.Println(output.String())
	}
	fmt.Println("LockTime:", tx.Locktime)
}

func (tx *Transaction)String() string {

	return "unfinished"
}

func (tx *Transaction)Parse(data string) error {
	var (
		err error
		tmp []byte
		i uint64
		oneInput = Input{}
		oneOutput = OutPut{}
		startIndex uint64
	)

	if tmp,err = hex.DecodeString(data[:8]);err !=  nil {
		return err
	}
	tx.Version = binary.LittleEndian.Uint32(tmp)

	if err = tx.InputCount.Parse(data[8:]); err != nil {
		return err
	}

	startIndex = uint64(8) + uint64(tx.InputCount.Len())*2
	for i=uint64(0); i<tx.InputCount.Value; i++ {
		if err = oneInput.Parse(data[startIndex:]);err != nil {
			return err
		}
		tx.Inputs = append(tx.Inputs, oneInput)
		startIndex = startIndex + oneInput.Len()*2
	}

	if err = tx.OutputCount.Parse(data[startIndex:]); err != nil {
		return err
	}

	startIndex = startIndex + uint64(tx.OutputCount.Len())*2
	for i=uint64(0); i<tx.OutputCount.Value; i++ {
		if err = oneOutput.Parse(data[startIndex:]); err != nil {
			return err
		}
		tx.OutPuts = append(tx.OutPuts, oneOutput)
		startIndex = startIndex + oneOutput.Len()*2
	}

	if tmp, err = hex.DecodeString(data[startIndex:]);err != nil {
		return err
	}
	tx.Locktime = binary.LittleEndian.Uint32(tmp)
	return nil
}

//参数分别是私钥，目标地址，金额，手续费，找零地址和留言
//其中转账金额和手续费都是无符号整数，单位是聪
//返回已签过名的交易数据，可直接去广播
func ConstructTransaction(privKey *secp256k1.PrivateKey,
	toAddr string,
	amount uint64,
	fee uint64,
	changeAddr string) ([]byte, error){
	// 参数校验
	if privKey == nil {
		return nil,errors.New("private key is nil")
	}
	//if !IsValidBtcAddress(toAddr) {
	//	return nil,errors.New("invalid to address")
	//}
	//if !IsValidBtcAddress(changeAddr) {
	//	return nil,errors.New("invalid change address")
	//}

	compressedPubKey := privKey.PubKey().SerializeCompressed()
	pubKeyHash, err := common.Ripemd160AfterSha256(compressedPubKey)
	if err != nil {
		return nil,err
	}
	addr := address.MustPubKeyHash2Address(pubKeyHash, "testnet")
	fmt.Println("address:", addr)
	//转账金额是否足够
	var addrInfo *AddressInfo
	if addrInfo, err = GetAddressInfo(addr); err != nil {
		return nil,err
	}

	//余额是否足够
	var targetAmount = amount + fee
	balance := addrInfo.GetBalance()
	if balance < targetAmount {
		return nil,errors.New("not enough balance")
	}

	//挑选utxo组建交易
	var allUTXO []UTXO
	var toUseUTXO []UTXO
	if allUTXO,err = addrInfo.GetUTXOs();err != nil {
		return nil,err
	}
	var amountSum = uint64(0)
	for _, oneUTXO := range allUTXO {
		if amountSum >= targetAmount {
			break
		}
		amountSum += oneUTXO.Amount
		toUseUTXO = append(toUseUTXO, oneUTXO)
	}
	var tx = Transaction{}
	tx.Version = 2 //
	tx.InputCount = NewVarInt(uint64(len(toUseUTXO)))
	for _, utxo := range toUseUTXO {
		var input = Input{}
		var buf []byte
		if buf,err = utils.ReverseBigEdianString(utxo.Txid);err != nil {//todo:该考虑这个函数的命名了
			return nil,err
		}
		copy(input.TxID[:], buf)
		input.VOUT = uint32(utxo.Vout)
		input.ScriptSigSize = NewVarInt(0)
		input.ScriptSig = nil
		input.Sequence = 0xffffffff
		tx.Inputs = append(tx.Inputs, input)
	}

	buf := base58.Decode(toAddr)
	var output = NewOutput(amount, buf[1:len(buf)-4])
	tx.OutPuts = append(tx.OutPuts, output)
	if amountSum > targetAmount { //处理找零OutPut
		buf = base58.Decode(changeAddr)
		output = NewOutput(amountSum-targetAmount, buf[1:len(buf)-4])
		tx.OutPuts = append(tx.OutPuts, output)
	}
	tx.OutputCount = NewVarInt(uint64(len(tx.OutPuts)))

	tx.Locktime = uint32(0)

	fmt.Println("unsigned transaction: ", hex.EncodeToString(tx.Serialize()))

	//签名.填充input[i].ScriptSig
	for i := range tx.Inputs {
		var txToSign = tx
		scriptPubKey, _ := hex.DecodeString(toUseUTXO[i].ScriptPubKey)
		txToSign.Inputs[i].ScriptSig = append(txToSign.Inputs[i].ScriptSig, scriptPubKey...)
		txToSign.Inputs[i].ScriptSigSize = NewVarInt(uint64(len(scriptPubKey)))
		buf = txToSign.Serialize()
		buf = append(buf, []byte{0x01,0x00,0x00,0x00}...)//加上小端序的SIGHASH_ALL
		hash256 := common.Sha256AfterSha256(buf)
		sig := ecdsa.Sign(privKey, hash256[:])

		sigInBytes := sig.Serialize()
		var r,s []byte
		r = append(r, sigInBytes[4:4+sigInBytes[3]]...)
		s = append(s, sigInBytes[4+sigInBytes[3]+2:]...)
		buf = privKey.PubKey().SerializeCompressed()
		ssig := NewScriptSigP2PKH(r, s, buf)
		tx.Inputs[i].ScriptSig = ssig.Serialize()
		tx.Inputs[i].ScriptSigSize = NewVarInt(uint64(len(tx.Inputs[i].ScriptSig)))
	}
	return tx.Serialize(),nil
}

func (tx *Transaction)Serialize() []byte {
	var data []byte
	var uint32Bytes [4]byte
	binary.LittleEndian.PutUint32(uint32Bytes[:], tx.Version)
	data = append(data, uint32Bytes[:]...)
	data = append(data, tx.InputCount.Data...)
	for i:=uint64(0); i< tx.InputCount.Value; i++ {
		data = append(data, tx.Inputs[i].Serialize()...)
	}
	data = append(data, tx.OutputCount.Data...)
	for i:=uint64(0); i< tx.OutputCount.Value; i++ {
		data = append(data, tx.OutPuts[i].Serialize()...)
	}
	binary.LittleEndian.PutUint32(uint32Bytes[:], tx.Locktime)
	data = append(data, uint32Bytes[:]...)
	return data
}

type AddressInfo struct {
	info string
	address string
}

func GetAddressInfo(address string) (*AddressInfo, error) {
	//参数校验
	//if !IsValidBtcAddress(address) {
	//	return nil,errors.New("invalid btc address")
	//}
	var (
		url = "https://api.blockchair.com/bitcoin/testnet/dashboards/address/" + address
		resp *http.Response
		err error
		body []byte
	)

	if resp , err =http.Get(url); err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		fmt.Println(err.Error())
		return nil,err
	}

	return &AddressInfo{address: address, info: string(body)},nil
}

//从info中解析出balance
func (addrInfo *AddressInfo)GetBalance() uint64 {
	balancePath := "data." + addrInfo.address + ".address.balance"
	return uint64(gojsonq.New().FromString(addrInfo.info).Find(balancePath).(float64))
}

type UTXO struct {
	Txid string
	Vout uint64
	Amount uint64
	ScriptPubKey string
}

//从info中解析出utxo
func (addrInfo *AddressInfo)GetUTXOs() ([]UTXO,error) {
	var retUtxo []UTXO
	var utxoList []interface{}
	var ok bool
	var err error
	utxoPath := "data." + addrInfo.address + ".utxo"
	if utxoList, ok = gojsonq.New().FromString(addrInfo.info).From(utxoPath).Select("transaction_hash", "index", "value").Get().([]interface{}); !ok { //不能强行转换成类型[]map[string]interface{}
		return nil, errors.New("convert utxo list error")
	}

	for _, elem := range utxoList {
		utxoMap, ok := elem.(map[string]interface{})
		if !ok {
			fmt.Println("convert utxo map error")
		}

		u := UTXO{}
		u.Txid = utxoMap["transaction_hash"].(string)
		u.Vout = uint64(utxoMap["index"].(float64))
		u.Amount = uint64(utxoMap["value"].(float64))
		if u.ScriptPubKey,err = GetScriptPubKey(u.Txid, u.Vout);err != nil {
			return nil, err
		}
		retUtxo = append(retUtxo, u)
	}
	return retUtxo,nil
}

func GetScriptPubKey(txid string, index uint64) (string, error) {
	//参数校验
	if len(txid) != 64 {
		return "",errors.New("invalid txid")
	}

		var (
			url = "https://api.blockchair.com/bitcoin/testnet/dashboards/transaction/" + txid
			resp *http.Response
			err error
			body []byte
		)

		if resp , err =http.Get(url); err != nil {
			fmt.Println(err.Error())
			return "", err
		}
		defer resp.Body.Close()

		if body, err = ioutil.ReadAll(resp.Body); err != nil {
			fmt.Println(err.Error())
			return "",err
		}

	spkPath := fmt.Sprintf("data.%s.outputs.[%d].script_hex", txid, index)//注意，output后面那个点千万不能丢
	script_hex := gojsonq.New().FromString(string(body)).Find(spkPath)
	script_str, _ := script_hex.(string) //need type assertion
	return script_str, nil
}