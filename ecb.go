package zmkutil

import "crypto/cipher"

var _ cipher.BlockMode = (*ecbEncrypter)(nil)

type ecbEncrypter struct {
	b cipher.Block
}

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return &ecbEncrypter{b}
}

func (x *ecbEncrypter) BlockSize() int { return x.b.BlockSize() }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.BlockSize() != 0 {
		panic("input not full blocks")
	}
	if len(dst) < len(src) {
		panic("output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.BlockSize()])
		src, dst = src[x.BlockSize():], dst[x.BlockSize():]
	}
}

var _ cipher.BlockMode = (*ecbDecrypter)(nil)

type ecbDecrypter struct {
	b cipher.Block
}

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return &ecbDecrypter{b}
}

func (x *ecbDecrypter) BlockSize() int { return x.b.BlockSize() }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.BlockSize() != 0 {
		panic("input not full blocks")
	}
	if len(dst) < len(src) {
		panic("output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.BlockSize()])
		src, dst = src[x.BlockSize():], dst[x.BlockSize():]
	}
}
