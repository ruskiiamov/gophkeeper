// Package cryptor is the AES-CTR cipher.
package cryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/ruskiiamov/gophkeeper/internal/data"
)

const keySize = 32

type builder struct{}

type cryptor struct {
	stream cipher.Stream
	slice  []byte
}

// New returns AES-CTR cipher builder.
func New() *builder {
	return &builder{}
}

// Make returns AES-CTR cipher.
func (b *builder) Make(key []byte) (data.Cipher, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("wrong key size")
	}

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new aes cipher creation error: %w", err)
	}

	iv := key[:aes.BlockSize]

	stream := cipher.NewCTR(aesBlock, iv)
	if err != nil {
		return nil, fmt.Errorf("new stream creation error: %w", err)
	}

	return &cryptor{stream: stream}, nil
}

// Crypt makes AES-CTR encryption/decryption of the provided slice of bytes.
func (c *cryptor) Crypt(chunk []byte) []byte {
	if len(c.slice) != len(chunk) {
		c.slice = make([]byte, len(chunk))
	}
	c.stream.XORKeyStream(c.slice, chunk)

	return c.slice
}
