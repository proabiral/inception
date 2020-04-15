package helpers

import (
	"fmt"
	"os"
)

func errCheck(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func WriteFile(json []byte, path string) {
	f, err := os.Create(path)
	errCheck(err)

	defer f.Close()
	_, err = f.Write(json)
	errCheck(err)
}
