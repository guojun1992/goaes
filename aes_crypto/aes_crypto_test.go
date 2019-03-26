package aes_crypto

import (
	"encoding/json"
	"log"
	"testing"
)

func TestAesEncrypt(t *testing.T) {
	userInfo := json.RawMessage(`{"name":"testname","age":20,"phone":18709870987}`)
	r, err := AesEncrypt(userInfo)
	if err != nil {
		panic(err)
	}

	log.Println("TestAesEncrypt: ", string(r))
}

func TestAesDecrypt(t *testing.T) {
	en_str := "%2FVT85XAkYmGdKurM0A59%2FlcXgSkuvDyZgBiZT8rZfaeOIuGRjFhIEQ%2Bqyf8AJQhe"
	r, err := AesDecrypt(en_str)
	if err != nil {
		panic(err)
	}

	log.Println("TestAesDecrypt: ", string(r))
}
