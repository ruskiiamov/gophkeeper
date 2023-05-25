package cryptor

import (
	"crypto/rand"
	"testing"

	"golang.org/x/exp/slices"
)

func TestCrypt(t *testing.T) {
	builder := New()

	wrongKey := make([]byte, 16)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatal(err)
	}
	_, err := builder.Make(wrongKey)
	if err == nil {
		t.Fatalf("cipher made with wrong key")
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	encryptCipher, err := builder.Make(key)
	if err != nil {
		t.Fatal(err)
	}

	decryptCipher, err := builder.Make(key)
	if err != nil {
		t.Fatal(err)
	}

	src := make([]byte, 64*1024)
	if _, err := rand.Read(src); err != nil {
		t.Fatal(err)
	}

	encrypted := encryptCipher.Crypt(src)
	decrypted := decryptCipher.Crypt(encrypted)

	if !slices.Equal(src, decrypted) {
		t.Fatalf("byte slices not equal")
	}
}