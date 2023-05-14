package cryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

const keySize = 32

type cryptor struct {
	encryptCipher cipher.Stream
	decryptCipher cipher.Stream
}

func New() *cryptor {
	return &cryptor{}
}

func (c *cryptor) SetKeys(encryptKey, decryptKey []byte) error {
	if encryptKey != nil {
		encryptCipher, err := createCipher(encryptKey)
		if err != nil {
			return fmt.Errorf("create encrypt cipher error: %w", err)
		}
		c.encryptCipher = encryptCipher
	}

	if decryptKey != nil {
		decryptCipher, err := createCipher(decryptKey)
		if err != nil {
			return fmt.Errorf("create decrypt cipher error: %w", err)
		}
		c.decryptCipher = decryptCipher
	}

	return nil
}

func (c *cryptor) Encrypt(chunk []byte) ([]byte, error) {
	if c.encryptCipher == nil {
		return nil, errors.New("encrypt key not set")
	}

	res := make([]byte, len(chunk))
	c.encryptCipher.XORKeyStream(res, chunk)

	return res, nil
}

func (c *cryptor) Decrypt(chunk []byte) ([]byte, error) {
	if c.decryptCipher == nil {
		return nil, errors.New("decrypt key not set")
	}

	res := make([]byte, len(chunk))
	c.encryptCipher.XORKeyStream(res, chunk)

	return res, nil
}

func createCipher(key []byte) (cipher.Stream, error) {
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

	return stream, nil
}
