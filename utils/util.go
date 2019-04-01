package utils

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"hash/adler32"
	"math/big"
	"net"
	"os"
	"regexp"
	"strings"
)

func Base64Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func Base64Decode(str string) string {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	return string(data)
}
func Base64EncodeRaw(str []byte) string {
	return base64.StdEncoding.EncodeToString(str)
}

func Base64DecodeRaw(str string) []byte {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil
	}
	return data
}

type DSAKeyFormat struct {
	Version       int
	P, Q, G, Y, X *big.Int
}

func FilenameObfuscator(path, ext string) string {
	filenameArr := strings.Split(path, string(os.PathSeparator))
	filename := filenameArr[len(filenameArr)-1]
	path2 := strings.Join(filenameArr[:len(filenameArr)-1], string(os.PathSeparator))

	return path2 + string(os.PathSeparator) + Base64Encode(filename) + ext

}
func FilenameDeobfuscator(path string, ext string) string {
	//get the path for the output
	opPath := strings.Trim(path, ext)
	// Divide filepath
	filenameArr := strings.Split(opPath, string(os.PathSeparator))
	//Get base64 encoded filename
	filename := filenameArr[len(filenameArr)-1]
	// get parent dir
	path2 := strings.Join(filenameArr[:len(filenameArr)-1], string(os.PathSeparator))
	return path2 + string(os.PathSeparator) + Base64Decode(filename)
}

func GetNetIPs(ips []interface{}) ([]net.IP, error) {
	if ips == nil {
		return []net.IP{}, nil
	}
	var ipStr string
	var ok bool
	var netIP net.IP
	netIPs := make([]net.IP, len(ips))
	for i, ip := range ips {
		ipStr, ok = ip.(string)
		if !ok {
			return nil, fmt.Errorf("error parsing ip: %v is not a string", ip)
		}
		netIP = net.ParseIP(ipStr)
		if netIP == nil {
			return nil, fmt.Errorf("error parsing ip: %s", ipStr)
		}
		netIPs[i] = netIP
	}
	return netIPs, nil
}

func GetAlternateDNSStrs(alternateDNS []interface{}) ([]string, error) {
	if alternateDNS == nil {
		return []string{}, nil
	}
	var dnsStr string
	var ok bool
	alternateDNSStrs := make([]string, len(alternateDNS))
	for i, dns := range alternateDNS {
		dnsStr, ok = dns.(string)
		if !ok {
			return nil, fmt.Errorf(
				"error processing alternate dns name: %v is not a string",
				dns,
			)
		}
		alternateDNSStrs[i] = dnsStr
	}
	return alternateDNSStrs, nil
}

func RegexMatch(regex string, s string) bool {
	match, _ := regexp.MatchString(regex, s)
	return match
}

func RegexFindAll(regex string, s string, n int) []string {
	r := regexp.MustCompile(regex)
	return r.FindAllString(s, n)
}

func RegexFind(regex string, s string) string {
	r := regexp.MustCompile(regex)
	return r.FindString(s)
}

func RegexReplaceAll(regex string, s string, repl string) string {
	r := regexp.MustCompile(regex)
	return r.ReplaceAllString(s, repl)
}

func RegexReplaceAllLiteral(regex string, s string, repl string) string {
	r := regexp.MustCompile(regex)
	return r.ReplaceAllLiteralString(s, repl)
}

func RegexSplit(regex string, s string, n int) []string {
	r := regexp.MustCompile(regex)
	return r.Split(s, n)
}

func Sha256sum(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func Sha1sum(input string) string {
	hash := sha1.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

func Adler32sum(input string) string {
	hash := adler32.Checksum([]byte(input))
	return fmt.Sprintf("%d", hash)
}

func Uuidv4() string {
	return fmt.Sprintf("%s", uuid.New())
}
