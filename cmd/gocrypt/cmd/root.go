// Copyright © 2019 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"github.com/autom8ter/gocrypt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var encrypt bool
var decrypt bool
var file string
var key string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: "gocrypt",
	Long: `
--------------------------------------------------------
  ______  _____  _______  ______ __   __  _____  _______
 |  ____ |     | |       |_____/   \_/   |_____]    |   
 |_____| |_____| |_____  |    \_    |    |          |
--------------------------------------------------------

a cli utility tool to easily encrypt and decrypt files

`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if key == "" {
			key = os.Getenv("SECRET")
			if key == "" {
				log.Fatalln("please provide a valid key with the -k flag or $SECRET environmental variable")
			}
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		var g = gocrypt.NewGoCrypt()

		switch {
		case decrypt && encrypt:
			log.Fatalln("cannot set mode to decrypt and encrypt simultaneously")
		case decrypt:
			if file == "" {
				log.Fatalln("please provide a valid file path with the -f flag")
			}
			log.Println("decrypting file: ", file)
			err := g.DecryptFiles(file, key, 0755)
			if err != nil {
				log.Fatalln(err.Error())
			}
		case encrypt:
			if file == "" {
				log.Fatalln("please provide a valid file path with the -f flag")
			}
			log.Println("encrypting file: ", file)
			err := g.EncryptFiles(file, key, 0755)
			if err != nil {
				log.Fatalln(err.Error())
			}
		default:
			fmt.Println(cmd.Long)
			fmt.Println(cmd.UsageString())
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&encrypt, "encrypt", "e", false, "set to encrypt mode")
	rootCmd.PersistentFlags().BoolVarP(&decrypt, "decrypt", "d", false, "set to decrypt mode")
	rootCmd.PersistentFlags().StringVarP(&file, "file", "f", "", "target file")
	rootCmd.PersistentFlags().StringVarP(&key, "key", "k", "", "encryption/decryption key ($SECRET)")
}
