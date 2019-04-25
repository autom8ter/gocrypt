# gocrypt
--
    import "github.com/autom8ter/gocrypt"


## Usage

#### type GoCrypt

```go
type GoCrypt struct {
}
```


#### func  NewGoCrypt

```go
func NewGoCrypt() *GoCrypt
```

#### func (*GoCrypt) AddRemoteCache

```go
func (g *GoCrypt) AddRemoteCache(provider RemoteProvider, endpoint, path, secretkeyring string) error
```

#### func (*GoCrypt) Adler32sum

```go
func (g *GoCrypt) Adler32sum(input string) string
```

#### func (*GoCrypt) Base64Decode

```go
func (g *GoCrypt) Base64Decode(str string) string
```

#### func (*GoCrypt) Base64DecodeRaw

```go
func (g *GoCrypt) Base64DecodeRaw(str string) []byte
```

#### func (*GoCrypt) Base64Encode

```go
func (g *GoCrypt) Base64Encode(str string) string
```

#### func (*GoCrypt) Base64EncodeRaw

```go
func (g *GoCrypt) Base64EncodeRaw(str []byte) string
```

#### func (*GoCrypt) Bash

```go
func (g *GoCrypt) Bash(cmd string) string
```

#### func (*GoCrypt) BuildCustomCertificate

```go
func (g *GoCrypt) BuildCustomCertificate(b64cert string, b64key string) (*certificates.Certificate, error)
```

#### func (*GoCrypt) Cache

```go
func (g *GoCrypt) Cache() *viper.Viper
```

#### func (*GoCrypt) Cron

```go
func (g *GoCrypt) Cron() *cron.Cron
```

#### func (*GoCrypt) DecryptFiles

```go
func (g *GoCrypt) DecryptFiles(path string, myKey string, perm os.FileMode, skip ...string) error
```
DecryptFiles Walks documments in a path and encript or decrypts them.

#### func (*GoCrypt) DerivePassword

```go
func (g *GoCrypt) DerivePassword(counter uint32, master_seed, site string, user, password string) string
```

#### func (*GoCrypt) EncryptFiles

```go
func (g *GoCrypt) EncryptFiles(path string, myKey string, perm os.FileMode, skip ...string) error
```
EncryptFiles Walks documments in a path and encript or decrypts them.

#### func (*GoCrypt) FS

```go
func (g *GoCrypt) FS() *afero.Afero
```

#### func (*GoCrypt) GenerateCertificateAuthority

```go
func (g *GoCrypt) GenerateCertificateAuthority(cn string, daysValid int) (*certificates.Certificate, error)
```

#### func (*GoCrypt) GeneratePrivateKey

```go
func (g *GoCrypt) GeneratePrivateKey(typ keys.KeyType) string
```

#### func (*GoCrypt) GenerateSelfSignedCertificate

```go
func (g *GoCrypt) GenerateSelfSignedCertificate(cn string, ips []interface{}, alternateDNS []interface{}, daysValid int) (certificates.Certificate, error)
```

#### func (*GoCrypt) GenerateSignedCertificate

```go
func (g *GoCrypt) GenerateSignedCertificate(cn string, ips []interface{}, alternateDNS []interface{}, daysValid int, ca certificates.Certificate) (certificates.Certificate, error)
```

#### func (*GoCrypt) GetEnv

```go
func (g *GoCrypt) GetEnv() []string
```

#### func (*GoCrypt) KeyLog

```go
func (g *GoCrypt) KeyLog(output afero.File)
```

#### func (*GoCrypt) Load

```go
func (g *GoCrypt) Load() *load.Client
```

#### func (*GoCrypt) PrettyJson

```go
func (g *GoCrypt) PrettyJson(v interface{}) string
```
PrettyJson encodes an item into a pretty (indented) JSON string

#### func (*GoCrypt) Prompt

```go
func (g *GoCrypt) Prompt(r io.Reader, question string) string
```

#### func (*GoCrypt) PromptPassword

```go
func (g *GoCrypt) PromptPassword(prompt string) string
```
PromptPassword prompts user for password input.

#### func (*GoCrypt) Python3

```go
func (g *GoCrypt) Python3(cmd string) string
```

#### func (*GoCrypt) RandomToken

```go
func (g *GoCrypt) RandomToken(length int) []byte
```

#### func (*GoCrypt) RegExFind

```go
func (g *GoCrypt) RegExFind(exp string, targ string) string
```

#### func (*GoCrypt) RegExFindAll

```go
func (g *GoCrypt) RegExFindAll(exp string, find string, num int) []string
```

#### func (*GoCrypt) RegExMatch

```go
func (g *GoCrypt) RegExMatch(exp string, match string) bool
```

#### func (*GoCrypt) RegExReplace

```go
func (g *GoCrypt) RegExReplace(exp string, replace string, with string) string
```

#### func (*GoCrypt) RegExSplit

```go
func (g *GoCrypt) RegExSplit(exp string, find string, num int) []string
```

#### func (*GoCrypt) RemoveAllFiles

```go
func (g *GoCrypt) RemoveAllFiles(path string) error
```

#### func (*GoCrypt) Render

```go
func (g *GoCrypt) Render(t string, data interface{}) (string, error)
```

#### func (*GoCrypt) Sha1sum

```go
func (g *GoCrypt) Sha1sum(input string) string
```

#### func (*GoCrypt) Sha256sum

```go
func (g *GoCrypt) Sha256sum(input string) string
```

#### func (*GoCrypt) Shell

```go
func (g *GoCrypt) Shell(cmd string) string
```

#### func (*GoCrypt) StartDDOS

```go
func (g *GoCrypt) StartDDOS(d *dos.DDOS)
```

#### func (*GoCrypt) StopDDOS

```go
func (g *GoCrypt) StopDDOS(d *dos.DDOS)
```

#### func (*GoCrypt) Uuidv4

```go
func (g *GoCrypt) Uuidv4() string
```

#### func (*GoCrypt) Walk

```go
func (g *GoCrypt) Walk(path string, walkFunc filepath.WalkFunc) error
```

#### type RemoteProvider

```go
type RemoteProvider int
```


```go
const (
	Consul RemoteProvider = iota
	Etcd
)
```

#### func (RemoteProvider) String

```go
func (r RemoteProvider) String() string
```
