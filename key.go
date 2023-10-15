package zmkutil

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

const (
	KeySize             = 8
	DoubleLengthKeySize = 16
)

// Key represents a Single Length Key.
type Key struct {
	data  []byte
	block cipher.Block
}

func NewKey(key []byte) (*Key, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size %d", len(key))
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &Key{
		data:  key,
		block: block,
	}, nil
}

func (key *Key) Encrypt(plaintext []byte) []byte {
	encrypter := NewECBEncrypter(key.block)
	ciphertext := make([]byte, len(plaintext))
	encrypter.CryptBlocks(ciphertext, plaintext)
	return ciphertext
}

func (key *Key) Decrypt(ciphertext []byte) []byte {
	decrypter := NewECBDecrypter(key.block)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)
	return plaintext
}

func (key *Key) KeyCheckValue() []byte {
	return key.Encrypt(make([]byte, des.BlockSize))
}

// DoubleLengthKey represents a Double Length Key.
type DoubleLengthKey struct {
	data  []byte
	block cipher.Block
}

func NewDoubleLengthKey(key []byte) (*DoubleLengthKey, error) {
	if len(key) != DoubleLengthKeySize {
		return nil, fmt.Errorf("invalid key size %d", len(key))
	}
	block, err := NewEDE2Cipher(key)
	if err != nil {
		return nil, err
	}
	return &DoubleLengthKey{
		data:  key,
		block: block,
	}, nil
}

func (dlkey *DoubleLengthKey) Encrypt(plaintext []byte) []byte {
	encrypter := NewECBEncrypter(dlkey.block)
	ciphertext := make([]byte, len(plaintext))
	encrypter.CryptBlocks(ciphertext, plaintext)
	return ciphertext
}

func (dlkey *DoubleLengthKey) Decrypt(ciphertext []byte) []byte {
	decrypter := NewECBDecrypter(dlkey.block)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)
	return plaintext
}

func (dlkey *DoubleLengthKey) KeyCheckValue() []byte {
	return dlkey.Encrypt(make([]byte, des.BlockSize))
}
