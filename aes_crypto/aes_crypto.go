package aes_crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"net/url"
)

/**
 * 使用aes加解密
 */

var aesKey = []byte("w2e4f3uhy8d2f8fl")

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncrypt(origData []byte) (string, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, aesKey[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	base64_crypted := base64.StdEncoding.EncodeToString(crypted)
	//urlencode处理base64编码后有斜杠和反斜杠等特殊符号
	encode_crypted := url.QueryEscape(base64_crypted)
	return encode_crypted, nil
}

func AesDecrypt(crypted string) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	decode_crypted, err := url.QueryUnescape(crypted)
	if err != nil {
		return nil, err
	}

	cryptedByte, err := base64.StdEncoding.DecodeString(decode_crypted)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, aesKey[:blockSize])
	origData := make([]byte, len(cryptedByte))
	blockMode.CryptBlocks(origData, cryptedByte)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}
