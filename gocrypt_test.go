package gocrypt_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/autom8ter/gocrypt"
	"strings"
	"testing"
)

func init() {
	g.Hack().Debug()
}

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

func TestDNS(t *testing.T) {
	resp, err := g.Hack().GetDNS(context.Background(), "google.com", "netfilx.com", "facebook.com")
	if err != nil {
		fmt.Println(g.PrettyJson(resp))
		t.Fatal(err.Error())
	}
	fmt.Println(g.PrettyJson(resp))
}

func TestReverseDNS(t *testing.T) {
	resp, err := g.Hack().ReverseDNS(context.Background(), "31.13.71.36", "172.217.12.206", "52.32.78.165")
	if err != nil {
		fmt.Println(g.PrettyJson(resp))
		t.Fatal(err.Error())
	}
	fmt.Println(g.PrettyJson(resp))
}

func TestMyIP(t *testing.T) {
	resp, err := g.Hack().GetMyIP(context.Background())
	if err != nil {
		fmt.Println(g.PrettyJson(resp))
		t.Fatal(err.Error())
	}
	fmt.Println(g.PrettyJson(resp))
}

func TestHeaders(t *testing.T) {
	resp, err := g.Hack().Headers(context.Background())
	if err != nil {
		fmt.Println(g.PrettyJson(resp))
		t.Fatal(err.Error())
	}
	fmt.Println(g.PrettyJson(resp))
}
