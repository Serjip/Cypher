package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/tv42/base58"
)

// Extesion of the chipher files
const Extension = ".cypher"

var Key []byte

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

	// Get the key
	var err error
	Key, err = key(password)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Check is directory of file
	var isDir bool
	isDir, err = IsDirectory(input)

	if decrypt {

		err = filepath.Walk(input, decryptWalker)

	} else {

		err = filepath.Walk(input, encryptWalker)

	}

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var skipPath string

func decryptWalker(path string, f os.FileInfo, err error) error {

	filename := f.Name()

	if err != nil {

		return err

	} else if strings.HasSuffix(filename, Extension) {

		// Decrypt name
		name := strings.TrimSuffix(filename, Extension)
		nameBytes := decodeBase58([]byte(name))

		nameBytes, err := decrypt(Key, nameBytes)
		if err != nil {
			return err
		}

		// read content from your file
		var data []byte
		data, err = ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		// Set new filepath
		newFilepath := strings.TrimSuffix(path, filename)
		newFilepath = fmt.Sprintf("%s%s", newFilepath, nameBytes)

		// Check the file existing
		if _, err := os.Stat(newFilepath); err == nil {
			fmt.Printf("%s file already exists\n", newFilepath)
			return nil
		}

		// create a new file for saving the encrypted data.
		var file *os.File
		file, err = os.Create(newFilepath)
		if err != nil {
			return err
		}

		// Encrypt file
		data, err = decrypt(Key, data)
		if err != nil {
			return err
		}

		_, err = io.Copy(file, bytes.NewReader(data))
		if err != nil {
			return err
		}

		// Finaly delete encrypted file
		err = os.Remove(path)
		if err != nil {
			return err
		}

		fmt.Printf("%s -> %s\n", filename, nameBytes)

		return nil
	}

	return nil
}

func encryptWalker(path string, f os.FileInfo, err error) error {

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

	// Encrypt name
	var encryptedName []byte
	encryptedName, err = encrypt(Key, []byte(filename))
	if err != nil {
		return err
	}
	encryptedName = encodeBase58(encryptedName)
	// Print it to console
	fmt.Printf("%s -> %s%s\n", filename, encryptedName, Extension)

	// read content from your file
	var data []byte
	data, err = ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	// Set new filepath
	newFilepath := strings.TrimSuffix(path, filename)
	newFilepath = fmt.Sprintf("%s%s%s", newFilepath, encryptedName, Extension)

	// create a new file for saving the encrypted data.
	var file *os.File
	file, err = os.Create(newFilepath)
	if err != nil {
		return err
	}

	// Encrypt file
	data, err = encrypt(Key, data)
	if err != nil {
		return err
	}

	_, err = io.Copy(file, bytes.NewReader(data))
	if err != nil {
		return err
	}

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
	return vector, nil
}

func IsDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	return fileInfo.IsDir(), err
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
