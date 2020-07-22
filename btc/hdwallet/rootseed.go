package hdwallet

import (
	"crypto/sha512"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"strings"
)

const (
	iterCount = 2048
	KeyLen = 64 //uint byte
)

//todo:HMAC-SHA512和SHA512有什么区别？
//助记词单词之间一定要用空格隔开，不能用其他符号隔开
func Mnemonics2RootSeed(mnemonics, passphrase string) ([]byte, error) {
	words := strings.Split(mnemonics, " ")
	wordAmount := len(words)
	if !(wordAmount >= 12 && wordAmount <=24 && wordAmount%3==0) {
		return nil,errors.New("invalid mnmonic words")
	}
	return pbkdf2.Key([]byte(mnemonics), []byte("mnemonic"+passphrase), iterCount, KeyLen, sha512.New ),nil
}
