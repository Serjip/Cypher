package coder

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"strings"

	"github.com/tv42/base58"
)

// Extesion of the chipher files
const Extension = ".cypher"

func EncryptFile(path string, f os.FileInfo, key []byte) error {

	// Encrypt name
	filename, err := encrypt(key, []byte(f.Name()))
	if err != nil {
		return err
	}
	filename = encodeBase58(filename)
	// Print it to console
	fmt.Printf("%s -> %s%s\n", f.Name(), filename, Extension)

	// read content from your file
	var data []byte
	data, err = ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	// Set new filepath
	newFilepath := strings.TrimSuffix(path, f.Name())
	newFilepath = fmt.Sprintf("%s%s%s", newFilepath, filename, Extension)

	// create a new file for saving the encrypted data.
	var file *os.File
	file, err = os.Create(newFilepath)
	if err != nil {
		return err
	}

	// Encrypt file
	data, err = encrypt(key, data)
	if err != nil {
		return err
	}

	_, err = io.Copy(file, bytes.NewReader(data))
	if err != nil {
		return err
	}

	return nil
}

func DecryptFile(path string, f os.FileInfo, key []byte) error {

	if f.IsDir() {
		text := fmt.Sprintf("%s is directory not a file", path)
		return errors.New(text)
	}

	if !strings.HasSuffix(f.Name(), Extension) {
		text := fmt.Sprintf("%s invalid filename. The file must have the extension %s", path, Extension)
		return errors.New(text)
	}

	// Decrypt name
	name := strings.TrimSuffix(f.Name(), Extension)
	nameBytes := decodeBase58([]byte(name))
	nameBytes, err := decrypt(key, nameBytes)

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
	newFilepath := strings.TrimSuffix(path, f.Name())
	newFilepath = fmt.Sprintf("%s%s", newFilepath, nameBytes)

	// Check the file existing
	if _, err := os.Stat(newFilepath); err == nil {
		text := fmt.Sprintf("%s file already exists\n", newFilepath)
		return errors.New(text)
	}

	// create a new file for saving the encrypted data.
	var file *os.File
	file, err = os.Create(newFilepath)
	if err != nil {
		return err
	}

	// Encrypt file
	data, err = decrypt(key, data)
	if err != nil {
		return err
	}

	_, err = io.Copy(file, bytes.NewReader(data))
	if err != nil {
		return err
	}

	fmt.Printf("%s -> %s\n", f.Name(), nameBytes)

	return nil
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
