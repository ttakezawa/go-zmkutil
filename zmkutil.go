package zmkutil

import (
	"crypto/des"
	"encoding/hex"
	"fmt"
)

const (
	SingleLengthZMKSize = des.BlockSize
	DoubleLengthZMKSize = des.BlockSize * 2
)

// SingleLengthZMK represents a Single Length Zone Master Key.
type SingleLengthZMK [SingleLengthZMKSize]byte

func (slzmk *SingleLengthZMK) EncryptKey(plainkey []byte) ([]byte, error) {
	block, err := des.NewCipher(slzmk[:])
	if err != nil {
		return nil, err
	}
	encrypter := NewECBEncrypter(block)
	cipherkey := make([]byte, len(plainkey))
	encrypter.CryptBlocks(cipherkey, plainkey)
	return cipherkey, nil
}

func (slzmk *SingleLengthZMK) DecryptKey(cipherkey []byte) ([]byte, error) {
	block, err := des.NewCipher(slzmk[:])
	if err != nil {
		return nil, err
	}
	decrypter := NewECBDecrypter(block)
	clearkey := make([]byte, len(cipherkey))
	decrypter.CryptBlocks(clearkey, cipherkey)
	return clearkey, nil
}

func (slzmk *SingleLengthZMK) KeyCheckValue() (string, error) {
	cipherkey, err := slzmk.EncryptKey(make([]byte, des.BlockSize))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%02X", cipherkey), nil
}

// DoubleLengthZMK represents a Double Length Zone Master Key.
type DoubleLengthZMK [DoubleLengthZMKSize]byte

func (dlzmk *DoubleLengthZMK) tripleDESKey() []byte {
	if len(dlzmk) != des.BlockSize*2 {
		panic(fmt.Errorf("invalid key length: %d", len(dlzmk)))
	}
	var tripleDESKey []byte
	tripleDESKey = append(tripleDESKey, dlzmk[:16]...)
	tripleDESKey = append(tripleDESKey, dlzmk[:8]...)
	return tripleDESKey
}

func (dlzmk *DoubleLengthZMK) EncryptKey(clearkey []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(dlzmk.tripleDESKey())
	if err != nil {
		return nil, err
	}
	encrypter := NewECBEncrypter(block)
	cipherkey := make([]byte, len(clearkey))
	encrypter.CryptBlocks(cipherkey, clearkey)
	return cipherkey, nil
}

func (dlzmk *DoubleLengthZMK) DecryptKey(cipherkey []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(dlzmk.tripleDESKey())
	if err != nil {
		return nil, err
	}
	decrypter := NewECBDecrypter(block)
	clearkey := make([]byte, len(cipherkey))
	decrypter.CryptBlocks(clearkey, cipherkey)
	return clearkey, nil
}

func (dlzmk *DoubleLengthZMK) KeyCheckValue() (string, error) {
	cipherkey, err := dlzmk.EncryptKey(make([]byte, des.BlockSize))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%02X", cipherkey), nil
}

// Component represents a part of a ZMK.
type Component []byte

// LoadComponent initializes new Component with given hex string.
func LoadComponent(hexStr string) (Component, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func MustLoadComponent(hexStr string) Component {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return bytes
}

func (c Component) KeyCheckValue() (string, error) {
	if len(c) == SingleLengthZMKSize {
		slzmk, err := FormSingleLengthZMK(c)
		if err != nil {
			return "", err
		}
		return slzmk.KeyCheckValue()
	} else if len(c) == DoubleLengthZMKSize {
		dlzmk, err := FormDoubleLengthZMK(c)
		if err != nil {
			return "", err
		}
		return dlzmk.KeyCheckValue()
	} else {
		return "", fmt.Errorf("invalid component size: %d", len(c))
	}
}

// FormSingleLengthZMK forms the ZMK from an arbitrary number of components
func FormSingleLengthZMK(components ...Component) (*SingleLengthZMK, error) {
	if len(components) < 1 {
		return nil, fmt.Errorf("at least one component is required to form a ZMK")
	}

	var slzmk SingleLengthZMK
	for _, k := range components {
		// check size
		if len(k) != SingleLengthZMKSize {
			return nil, fmt.Errorf("invalid component size: %d", len(k))
		}
		for i := 0; i < SingleLengthZMKSize; i++ {
			slzmk[i] ^= k[i]
		}
	}
	return &slzmk, nil
}

// FormDoubleLengthZMK forms the ZMK from an arbitrary number of components
func FormDoubleLengthZMK(components ...Component) (*DoubleLengthZMK, error) {
	if len(components) < 1 {
		return nil, fmt.Errorf("at least one component is required to form a ZMK")
	}

	var dlzmk DoubleLengthZMK
	for _, k := range components {
		// check size
		if len(k) != DoubleLengthZMKSize {
			return nil, fmt.Errorf("invalid component size: %d", len(k))
		}
		for i := 0; i < DoubleLengthZMKSize; i++ {
			dlzmk[i] ^= k[i]
		}
	}
	return &dlzmk, nil
}

// MustFormSingleLengthZMK is like FormSingleLengthZMK but panics on error.
func MustFormSingleLengthZMK(components ...Component) *SingleLengthZMK {
	zmk, err := FormSingleLengthZMK(components...)
	if err != nil {
		panic(err)
	}
	return zmk
}

// MustFormDoubleLengthZMK is like FormDoubleLengthZMK but panics on error.
func MustFormDoubleLengthZMK(components ...Component) *DoubleLengthZMK {
	zmk, err := FormDoubleLengthZMK(components...)
	if err != nil {
		panic(err)
	}
	return zmk
}
