package gocrypt_test

import (
	"errors"
	"fmt"
	"github.com/autom8ter/gocrypt"
	"strings"
	"testing"
)

var g = gocrypt.NewGoCrypt()
var key = "a very very very very secret key"

func TestNewGoCrypt(t *testing.T) {
	if g == nil {
		t.Fatal(errors.New("shouldnt be nil"))
	}
}

func TestGoCrypt_DerivePassword(t *testing.T) {
	if got := g.DerivePassword(8, "hello", "google.com", "coleman", "Password"); got != "HuveMogo3&Naqa" {
		t.Fatal(errors.New("expected HuveMogo3&Naqa, got: " + got))
	}
}

func TestGoCrypt_Bash(t *testing.T) {
	fmt.Println(g.Bash(`echo "hello world"`))
	if got := g.Bash(`echo "hello world"`); got != "hello world" {
		t.Fatalf("got: %s length: %v\nexpected: %s length: %v\n", got, len(got), "hello world", len("hello world"))
	}
}

func TestGoCrypt_Prompt(t *testing.T) {
	reader := strings.NewReader("Coleman\r\n") //Simulates the user typing "Coleman" and hitting the [enter] key
	ans := g.Prompt(reader, "whats your name?")
	if ans != "Coleman" {
		t.Fatalf("expected: %s\n got: %s\n", "Coleman", ans)
	}
	fmt.Println("name ", ans)
}

func TestGoCrypt_EncryptDocuments(t *testing.T) {
	if err := g.EncryptFiles("testing", key, 0755); err != nil {
		t.Fatal(err.Error())
	}

}

func TestGoCrypt_DecryptDocuments(t *testing.T) {
	if err := g.DecryptFiles("testing", key, 0755); err != nil {
		t.Fatal(err.Error())
	}
}

func TestGoCrypt_Python3(t *testing.T) {
	fmt.Println(g.Python3("a='example';print(a)"))
}
