package gocrypt

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Masterminds/sprig"
	"github.com/autom8ter/gocrypt/certificates"
	"github.com/autom8ter/gocrypt/dos"
	"github.com/autom8ter/gocrypt/encrypt"
	"github.com/autom8ter/gocrypt/fs"
	"github.com/autom8ter/gocrypt/keylogger"
	"github.com/autom8ter/gocrypt/keys"
	"github.com/autom8ter/gocrypt/passwords"
	"github.com/autom8ter/gocrypt/utils"
	"github.com/howeyc/gopass"
	"github.com/spf13/afero"
	"github.com/spf13/viper"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

type GoCrypt struct {
	cache *viper.Viper
}

func NewGoCrypt() *GoCrypt {
	c := viper.Sub("gocrypt")
	c.SetFs(fs.FS())
	return &GoCrypt{
		cache: c,
	}
}

func (g *GoCrypt) Cache() *viper.Viper {
	return g.cache
}

// PrettyJson encodes an item into a pretty (indented) JSON string
func (g *GoCrypt) PrettyJson(v interface{}) string {
	output, _ := json.MarshalIndent(v, "", "  ")
	return string(output)
}

func (g *GoCrypt) Sha256sum(input string) string {
	return utils.Sha256sum(input)
}

func (g *GoCrypt) Sha1sum(input string) string {
	return utils.Sha1sum(input)
}

func (g *GoCrypt) Adler32sum(input string) string {
	return utils.Adler32sum(input)
}

func (g *GoCrypt) Uuidv4() string {
	return utils.Uuidv4()
}

func (g *GoCrypt) GeneratePrivateKey(typ keys.KeyType) string {
	return typ.Generate()
}

func (g *GoCrypt) BuildCustomCertificate(b64cert string, b64key string) (*certificates.Certificate, error) {
	return certificates.BuildCustomCertificate(b64cert, b64key)
}

func (g *GoCrypt) GenerateCertificateAuthority(cn string, daysValid int) (*certificates.Certificate, error) {
	return certificates.GenerateCertificateAuthority(cn, daysValid)
}

func (g *GoCrypt) GenerateSelfSignedCertificate(cn string, ips []interface{}, alternateDNS []interface{}, daysValid int) (certificates.Certificate, error) {
	return certificates.GenerateSelfSignedCertificate(cn, ips, alternateDNS, daysValid)
}

func (g *GoCrypt) GenerateSignedCertificate(cn string, ips []interface{}, alternateDNS []interface{}, daysValid int, ca certificates.Certificate) (certificates.Certificate, error) {
	return certificates.GenerateSignedCertificate(cn, ips, alternateDNS, daysValid, ca)
}

// EncryptDocumets Walks documments in a path and encript or decrypts them.
func (g *GoCrypt) EncryptDocuments(myKey []byte, path string, mode encrypt.EncryptMode) error {
	return encrypt.EncryptDocuments(myKey, path, mode)
}

func (g *GoCrypt) Prompt(question string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(question)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	text = strings.TrimRight(text, "`")
	text = strings.TrimLeft(text, "`")
	if strings.Contains(text, "?") {
		newtext := strings.Split(text, "?")
		text = newtext[0]
	}
	return text
}

func (g *GoCrypt) Render(t string, data interface{}) (string, error) {
	if strings.Contains(t, "{{") {
		tmpl, err := template.New("").Funcs(sprig.GenericFuncMap()).Parse(t)
		if err != nil {
			return t, err
		}
		buf := bytes.NewBuffer(nil)
		if err := tmpl.Execute(buf, data); err != nil {
			if err != nil {
				return t, err
			}
		}
		return buf.String(), nil
	}
	return t, nil
}

func (g *GoCrypt) StartDDOS(d *dos.DDOS) {
	d.Start()
}

func (g *GoCrypt) StopDDOS(d *dos.DDOS) {
	d.Stop()
}

func (g *GoCrypt) DerivePassword(counter uint32, site string, user, password string) {
	passwords.DerivePassword(counter, passwords.Long, password, user, site)
}

// PromptPassword prompts user for password input.
func (g *GoCrypt) PromptPassword(prompt string) string {
	fmt.Printf(prompt)
	b, err := gopass.GetPasswd()
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}
	return string(b)
}

func (g *GoCrypt) GetEnv() []string {
	return os.Environ()
}

func (g *GoCrypt) Shell(cmd string) string {
	e := exec.Command("/bin/sh", "-c", cmd)
	res, _ := e.Output()
	return string(res)
}

func (g *GoCrypt) Bash(cmd string) string {
	e := exec.Command("/bin/bash", "-c", cmd)
	res, _ := e.Output()
	return string(res)
}

func (g *GoCrypt) Base64Encode(str string) string {
	return utils.Base64Encode(str)
}

func (g *GoCrypt) Base64Decode(str string) string {
	return utils.Base64Decode(str)
}

func (g *GoCrypt) Base64EncodeRaw(str []byte) string {
	return utils.Base64EncodeRaw(str)
}

func (g *GoCrypt) Base64DecodeRaw(str string) []byte {
	return utils.Base64DecodeRaw(str)
}

func (g *GoCrypt) ZipFile(zippedName string, files []string) error {
	return fs.ZipFiles(zippedName, files)
}

func (g *GoCrypt) AddFilesToZip(writer *zip.Writer, name string) error {
	return fs.AddFileToZip(writer, name)
}

func (g *GoCrypt) RegExFind(exp string, targ string) string {
	return utils.RegexFind(exp, targ)
}

func (g *GoCrypt) RegExReplace(exp string, replace string, with string) string {
	return utils.RegexReplaceAll(exp, replace, with)
}

func (g *GoCrypt) RegExFindAll(exp string, find string, num int) []string {
	return utils.RegexFindAll(exp, find, num)
}

func (g *GoCrypt) RegExSplit(exp string, find string, num int) []string {
	return utils.RegexSplit(exp, find, num)
}

func (g *GoCrypt) RegExMatch(exp string, match string) bool {
	return utils.RegexMatch(exp, match)
}

func (g *GoCrypt) CopyFile(src, dst string) (*afero.File, error) {
	return fs.CopyFile(src, dst)
}

func (g *GoCrypt) ChDir(path string) {
	fs.ChDir(path)
}

func (g *GoCrypt) ScanAndReplaceFile(file afero.File, replacements ...string) {
	fs.ScanAndReplaceFile(file, replacements...)
}

func (g *GoCrypt) OpenFile(path string) (afero.File, error) {
	return fs.Open(path)
}

func (g *GoCrypt) RemoveAllFiles(path string) error {
	return os.RemoveAll(path)
}

func (g *GoCrypt) Walk(path string, walkFunc filepath.WalkFunc) error {
	return filepath.Walk(path, walkFunc)
}

func (g *GoCrypt) KeyLog(output afero.File) {
	keylogger.LogKeys(output)
}
