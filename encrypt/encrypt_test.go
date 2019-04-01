package encrypt_test

import (
	"github.com/autom8ter/gocrypt/encrypt"
	"path/filepath"
	"testing"
)

var key = "a very very very very secret key"

func TestEncryptPath(t *testing.T) {
	if err := filepath.Walk("testing", encrypt.EncryptPath(key, 0755, "")); err != nil {
		t.Fatal(err.Error())
	}
}

func TestDecryptPath(t *testing.T) {
	if err := filepath.Walk("testing", encrypt.DecryptPath(key, 0755)); err != nil {
		t.Fatal(err.Error())
	}
}
