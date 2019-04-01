package gocrypt_test

import (
	"errors"
	"github.com/autom8ter/gocrypt"
	"testing"
)

func TestNewGoCrypt(t *testing.T) {
	g := gocrypt.NewGoCrypt()
	if g == nil {
		t.Fatal(errors.New("shouldnt be nil"))
	}
}
