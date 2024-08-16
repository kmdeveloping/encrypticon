package encrypticon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
)

type EncryptManager struct {
	EncodingKey string
}

func NewEncryptManager(encodingKey string) *EncryptManager {
	return &EncryptManager{EncodingKey: prepareKey(encodingKey)}
}

func (crypt *EncryptManager) Encrypt(value string) string {
	key, _ := hex.DecodeString(crypt.EncodingKey)
	pt := []byte(value)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(pt))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], pt)

	return base64.URLEncoding.EncodeToString(ciphertext)
}

func (crypt *EncryptManager) Decrypt(encryptedValue string) string {
	key, _ := hex.DecodeString(crypt.EncodingKey)
	ciphertext, _ := base64.URLEncoding.DecodeString(encryptedValue)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}

func prepareKey(key string) string {
	bytes := []byte(key)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Encryption Key Error: %s", err.Error())
	}

	return hex.EncodeToString(bytes)
}
