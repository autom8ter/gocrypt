package passwords

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"log"
	"os"
)

func init() {
	if master_password_seed == "" {
		log.Println("master password seed not set... setting default: default")
		master_password_seed = "default"
	}
}

var master_password_seed = os.Getenv("MASTER_PASSWORD_SEED")

type PasswordType int

const (
	Maximum PasswordType = iota
	Long
	Medium
	Short
	Basic
	Pin
)

var password_type_templates = map[PasswordType][][]byte{
	Maximum: {[]byte("anoxxxxxxxxxxxxxxxxx"), []byte("axxxxxxxxxxxxxxxxxno")},
	Long: {[]byte("CvcvnoCvcvCvcv"), []byte("CvcvCvcvnoCvcv"), []byte("CvcvCvcvCvcvno"), []byte("CvccnoCvcvCvcv"), []byte("CvccCvcvnoCvcv"),
		[]byte("CvccCvcvCvcvno"), []byte("CvcvnoCvccCvcv"), []byte("CvcvCvccnoCvcv"), []byte("CvcvCvccCvcvno"), []byte("CvcvnoCvcvCvcc"),
		[]byte("CvcvCvcvnoCvcc"), []byte("CvcvCvcvCvccno"), []byte("CvccnoCvccCvcv"), []byte("CvccCvccnoCvcv"), []byte("CvccCvccCvcvno"),
		[]byte("CvcvnoCvccCvcc"), []byte("CvcvCvccnoCvcc"), []byte("CvcvCvccCvccno"), []byte("CvccnoCvcvCvcc"), []byte("CvccCvcvnoCvcc"),
		[]byte("CvccCvcvCvccno")},
	Medium: {[]byte("CvcnoCvc"), []byte("CvcCvcno")},
	Short:  {[]byte("Cvcn")},
	Basic:  {[]byte("aaanaaan"), []byte("aannaaan"), []byte("aaannaaa")},
	Pin:    {[]byte("nnnn")},
}

var template_characters = map[byte]string{
	'V': "AEIOU",
	'C': "BCDFGHJKLMNPQRSTVWXYZ",
	'v': "aeiou",
	'c': "bcdfghjklmnpqrstvwxyz",
	'A': "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
	'a': "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
	'n': "0123456789",
	'o': "@&%?,=[]_:-+*$#!'^~;()/.",
	'x': "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
}

func DerivePassword(counter uint32, passType PasswordType, password, user, site string) string {
	var templates = password_type_templates[passType]
	if templates == nil {
		return fmt.Sprintf("cannot find password template %v", passType)
	}

	var buffer bytes.Buffer
	buffer.WriteString(master_password_seed)
	binary.Write(&buffer, binary.BigEndian, uint32(len(user)))
	buffer.WriteString(user)

	salt := buffer.Bytes()
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 2, 64)
	if err != nil {
		return fmt.Sprintf("failed to derive password: %s", err)
	}

	buffer.Truncate(len(master_password_seed))
	binary.Write(&buffer, binary.BigEndian, uint32(len(site)))
	buffer.WriteString(site)
	binary.Write(&buffer, binary.BigEndian, counter)

	var hmacv = hmac.New(sha256.New, key)
	hmacv.Write(buffer.Bytes())
	var seed = hmacv.Sum(nil)
	var temp = templates[int(seed[0])%len(templates)]

	buffer.Truncate(0)
	for i, element := range temp {
		pass_chars := template_characters[element]
		pass_char := pass_chars[int(seed[i+1])%len(pass_chars)]
		buffer.WriteByte(pass_char)
	}

	return buffer.String()
}
