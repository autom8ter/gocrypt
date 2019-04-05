# GoCrypt

`go get github.com/autom8ter/gocrypt`

A library written in golang for filesystem and security operations

## Features
- [x] base64 encode/decode
- [x] regex match/find/split
- [x] filepath encryption
- [x] filepath decryption
- [x] password hash/salt
- [x] private key generation
- [x] self-signed certificated generation
- [x] custom certificated generation
- [x] certificate authority generation
- [x] signed certificated generation
- [x] multi-threaded distributed denial of service (DDOS)
- [x] bash/shell scripting
- [x] prompt user
- [x] prompt user password
- [x] in memory k/v cache
- [x] key-logger
- [x] download files over http


## GoCrypt CLI

`go get github.com/autom8ter/gocrypt/cmd/gocrypt
`



```text

--------------------------------------------------------
  ______  _____  _______  ______ __   __  _____  _______
 |  ____ |     | |       |_____/   \_/   |_____]    |   
 |_____| |_____| |_____  |    \_    |    |          |
--------------------------------------------------------

a cli utility tool to easily encrypt and decrypt files


Usage:
  gocrypt [flags]
  gocrypt [command]

Available Commands:
  help        Help about any command
  read        unencrypt a file at runtime, print the contents to stdout, and then re-encrypt

Flags:
  -d, --decrypt       set to decrypt mode
  -e, --encrypt       set to encrypt mode
  -f, --file string   target file
  -h, --help          help for gocrypt
  -k, --key string    encryption/decryption key ($GOCRYPT_KEY)

Use "gocrypt [command] --help" for more information about a command.




```