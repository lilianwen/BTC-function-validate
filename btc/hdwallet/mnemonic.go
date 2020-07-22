package hdwallet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/ethereum/go-ethereum/common/math"
	"math/big"
	"strings"
)

const(
	mnemonicBitLen = 11 //每个助记词用11bit表示下标
)

// checkSumBitLen 范围[4 5 6 7 8]
func entropy2Mnemonics(entropy *big.Int, checkSumBitLen uint8) ([]string, error) {
	//参数校验
	if entropy == nil || !(checkSumBitLen <= 8 && checkSumBitLen%4 == 0)  {
		return nil, errors.New("invalid parameters")
	}

	var (
		hash256 [32]byte
		checkSumMask byte
		checkSum byte
		mask = big.NewInt((1<<mnemonicBitLen)-1)//11bit全是1
		mnemonics []string
		index big.Int
		wordAmount uint32
	)

	hash256 = sha256.Sum256(entropy.Bytes())
	if checkSumBitLen == 8 {//解决1左移8位导致byte溢出的问题
		checkSumMask = 0xff
	} else {
		checkSumMask = ^((1<<checkSumBitLen)-1)
	}

	checkSum = (hash256[0]&checkSumMask)>>(8-checkSumBitLen)
	entropy.Lsh(entropy, uint(checkSumBitLen))
	entropy.Or(entropy, big.NewInt(int64(checkSum)))

	//开始取字符串
	wordAmount = uint32((entropy.BitLen()+int(checkSumBitLen))/mnemonicBitLen)
	mnemonics = make([]string, wordAmount)
	for i:=uint32(0); i<wordAmount; i++ {
		//每11bit值取出来，当做助记词在wordlist里的下标
		mnemonics[wordAmount-i-1] = English[index.And(entropy, mask).Int64()]
		entropy.Rsh(entropy, mnemonicBitLen)
	}
	return mnemonics,nil
}

// num表示助记词个数[12,15,18,21,24]
func NewMnemonics(num uint8) ([]string, error) {
	//参数校验
	if !(num >= 12 && num <=24 && num%3==0) {
		return nil, errors.New("invalid parameter num")
	}

	var (
		entropy *big.Int
		entropyLenInBits = 32*(num/3)
		entropyMax *big.Int
		err error
	)
	entropyMax = new(big.Int).Sub(math.BigPow(2, int64(entropyLenInBits)), big.NewInt(1))
	if entropy,err = rand.Int(rand.Reader, entropyMax); err != nil {
		return nil, err
	}
	return entropy2Mnemonics(entropy, entropyLenInBits/32)
}

//传入助记词句子，每个单词用空格符隔开
func Mnemonics2Entropy(words string) (string, error) {
	//参数校验
	var wordList = strings.Split(words, " ")
	var wordAmount = uint(len(wordList))
	if  !(wordAmount >= 12 && wordAmount <= 24 && wordAmount%3 ==0) {
		return "", errors.New("invalid mnemonic word")
	}

	var (
		mnemonicMap = words2Map()
		entropy = big.NewInt(0)
		mnemonicIndex uint64
	)

	for i:=uint(0); i<wordAmount; i++ {
		mnemonicIndex = mnemonicMap[wordList[i]]
		entropy.Lsh(entropy, mnemonicBitLen)
		entropy.Or(entropy, new(big.Int).SetUint64(mnemonicIndex))
	}
	//此时算出来的是entropy|checksum,需要把checksum截去不用
	entropy.Rsh(entropy, wordAmount/3)
	return hex.EncodeToString(entropy.Bytes()),nil
}