package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func NewCipher(token []byte) (cipher.Block, error) {
	block, err := aes.NewCipher(token)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func EncryptPath(key string, perm os.FileMode, skip ...string) filepath.WalkFunc {
	keybits := []byte(key) // 32 bytes
	return func(path string, info os.FileInfo, err error) error {
		for _, p := range skip {
			if strings.Contains(path, p) {
				log.Printf("skipping file: %s\n", path)
				return nil
			}
		}
		if filepath.Ext(path) == ".enc" {
			log.Printf("skipping file with .enc extension: %s\n", path)
			return nil
		}
		if info.IsDir() {
			log.Printf("skipping directory: %s\n", path)
			return nil
		}
		if err != nil {
			return err
		}
		bits, err := ioutil.ReadFile(path)
		encrypted, err := encrypt(keybits, bits)
		if err != nil {
			return err
		}
		log.Printf("encrypting target file: %s\n", path)
		if err := ioutil.WriteFile(path+".enc", encrypted, perm); err != nil {
			return err
		}
		log.Printf("removing unencrypted files: %s\n", path)
		if err := os.RemoveAll(path); err != nil {
			return err
		}
		return nil
	}
}

func DecryptPath(key string, perm os.FileMode, skip ...string) filepath.WalkFunc {
	keybits := []byte(key) // 32 bytes
	return func(path string, info os.FileInfo, err error) error {
		for _, p := range skip {
			if strings.Contains(path, p) {
				log.Printf("skipping file: %s\n", path)
				return nil
			}
		}
		if filepath.Ext(path) != ".enc" {
			log.Printf("skipping path: %s\n", path)
			return nil
		}
		bits, err := ioutil.ReadFile(path)
		decrypted, err := decrypt(keybits, bits)
		if err != nil {
			return err
		}
		newpath := strings.TrimSuffix(path, ".enc")
		if exists(newpath) {
			log.Printf("removing old files: %s\n", newpath)
			if err := os.RemoveAll(newpath); err != nil {
				return err
			}
		}
		log.Printf("removing encrypted files: %s\n", path)
		if err := os.RemoveAll(path); err != nil {
			return err
		}
		log.Printf("writing unencrypted files: %s\n", newpath)
		if err := ioutil.WriteFile(newpath, decrypted, perm); err != nil {
			return err
		}
		return nil
	}
}

// See alternate IV creation from ciphertext below
//var iv = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// exists checks if a file or directory exists.
func exists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if !os.IsNotExist(err) {
		er(err)
	}
	return false
}

func er(msg interface{}) {
	fmt.Println("Error:", msg)
	os.Exit(1)
}

// isEmpty checks if a given path is empty.
// Hidden files in path are ignored.
func isEmpty(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		er(err)
	}

	if !fi.IsDir() {
		return fi.Size() == 0
	}

	f, err := os.Open(path)
	if err != nil {
		er(err)
	}
	defer f.Close()

	names, err := f.Readdirnames(-1)
	if err != nil && err != io.EOF {
		er(err)
	}

	for _, name := range names {
		if len(name) > 0 && name[0] != '.' {
			return false
		}
	}
	return true
}
