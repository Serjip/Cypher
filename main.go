package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Serjip/cypher/coder"
)

var Key []byte
var skipPath string

func main() {

	var password, path string
	var decrypt, recursive bool

	flag.StringVar(&password, "p", "", "password	 for encrypt/decrypt files")
	flag.StringVar(&path, "i", "", "input file or directory path")
	flag.BoolVar(&decrypt, "d", false, "decrypt file or directory. default false")
	flag.BoolVar(&recursive, "R", false, "recursive directories")
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

	if len(path) == 0 {

		var err error
		path, err = os.Getwd()
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

	// Get file info about the input path
	fileInfo, err := os.Stat(path)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// If the file has Extension .cypher
	// And set default action decrypt
	if !fileInfo.IsDir() && strings.HasSuffix(fileInfo.Name(), coder.Ext) && !decrypt {
		decrypt = true
	}

	// Choouse decrypt or encrypt filepath
	if decrypt {

		// If its directory check recursivity
		if fileInfo.IsDir() {

			if recursive {

				err = filepath.Walk(path, decryptWalker)

			} else {

				err = WalkNoneRecursive(path, decryptWalker)

			}
			// Otherwise decrypt the file
		} else {

			err = coder.DecryptFile(path, fileInfo, Key)
			if err == nil {
				remove(path, fileInfo)
			}
		}

	} else {

		// If its directory check recursivity
		if fileInfo.IsDir() {

			if recursive {

				err = filepath.Walk(path, encryptWalker)

			} else {

				err = WalkNoneRecursive(path, encryptWalker)

			}

		} else {

			err = coder.EncryptFile(path, fileInfo, Key)
			if err == nil {
				remove(path, fileInfo)
			}
		}

	}

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func WalkNoneRecursive(root string, walkFn filepath.WalkFunc) error {

	files, err := ioutil.ReadDir(root)
	for _, f := range files {

		filepath := filepath.Join(root, f.Name())
		if err = walkFn(filepath, f, err); err != nil {
			return err
		}
	}

	return nil
}

func decryptWalker(path string, f os.FileInfo, err error) error {

	if err != nil {

		return err

	} else if !f.IsDir() && strings.HasSuffix(f.Name(), coder.Ext) {

		err = coder.DecryptFile(path, f, Key)

		if err == nil {
			remove(path, f)
		}
	}
	return err
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

	} else if strings.HasSuffix(filename, coder.Ext) {

		return nil
	}

	err = coder.EncryptFile(path, f, Key)
	if err == nil {
		remove(path, f)
	}
	return err
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

func remove(path string, f os.FileInfo) {

	fmt.Printf("remove %s? ", f.Name())
	var text string
	fmt.Scan(&text)
	switch strings.ToLower(text) {
	case "y", "yes", "yeah", "yep", "yea", "yup", "true":
		os.Remove(path)
	case "n", "no", "nope", "not", "nay", "nix", "false":
		break
	default:
		fmt.Println("Invalid input. Type yes or no.")
		remove(path, f)
	}
}
