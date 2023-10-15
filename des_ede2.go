package zmkutil

import (
	"crypto/cipher"
	"crypto/des"
)

// NewEDE2Cipher creates and returns a new cipher.Block.
func NewEDE2Cipher(key []byte) (cipher.Block, error) {
	if len(key) != 16 {
		return nil, des.KeySizeError(len(key))
	}
	var tDESKey []byte
	tDESKey = append(tDESKey, key[:16]...)
	tDESKey = append(tDESKey, key[:8]...)
	return des.NewTripleDESCipher(tDESKey)
}
