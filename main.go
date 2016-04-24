package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	if err != nil {

		return err

	} else if len(skipPath) > 0 && strings.HasPrefix(path, skipPath) {

		return nil

	} else if string(f.Name()[0]) == "." {

		skipPath = path
		return nil

	} else if f.IsDir() {

		return nil

	} else if strings.HasSuffix(f.Name(), Extension) {

		return nil
	}

	fmt.Printf("Visited: %s\n", path)

	return nil
}
