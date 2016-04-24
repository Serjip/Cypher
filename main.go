package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/tv42/base58"
)

const Extension = ".cypher"

func main() {
	fmt.Println("Hello")

	var password, input string
	var decrypt bool
	flag.StringVar(&password, "p", "", "-password	for encrypt/decrypt files")
	flag.StringVar(&input, "i", "", "-input	file or directory")
	flag.BoolVar(&decrypt, "d", false, "--decrypt	input")

	flag.Parse()

	if len(password) == 0 {

		// Get password
		fmt.Print("Enter a password:")
		fmt.Scan(&password)

		// Get conformation
		var conformation string
		fmt.Print("Confirm a password:")
		fmt.Scan(&conformation)

		if password != conformation {
			fmt.Println("Passwords does not match")
			os.Exit(1)
		}
	}

	if len(input) == 0 {

		var err error
		input, err = os.Getwd()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	err := filepath.Walk(input, visit)
	fmt.Printf("filepath.Walk() returned %v\n", err)
}

var skipPath string

func visit(path string, f os.FileInfo, err error) error {

	filename := f.Name()

	if err != nil {

		return err

	} else if len(skipPath) > 0 && strings.HasPrefix(path, skipPath) {

		return nil

	} else if string(filename[0]) == "." {

		skipPath = path
		return nil

	} else if f.IsDir() {

		return nil

	} else if strings.HasSuffix(filename, Extension) {

		return nil
	}

	key := key(password)

	encName, err := encrypt([]byte("example key 1234"), []byte(filename))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s -> %s%s(%s)\n", filename, encodeBase58(encName), Extension, encName)

	return nil
}

func key(text string) ([]byte, error) {
	len := len(text)
	if len < 16 {
		len = 16
	} else if len < 24 {
		len = 24
	} else if len < 32 {
		len = 32
	} else {
		return nil, errors.New("The password cannot be more than 32 char")
	}
	vector := make([]byte, len)
	copy(vector[:], text)
	return vector
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)
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
	return text, nil
}

func encodeBase58(text []byte) []byte {
	num := new(big.Int)
	num.SetBytes(text)
	return base58.EncodeBig(nil, num)
}

func decodeBase58(text []byte) []byte {
	dec, _ := base58.DecodeToBig(text)
	return dec.Bytes()
}
