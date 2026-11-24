//go:build !unix

package sdcreds

import (
	"errors"
	"os"
)

var errNoHostFile = errors.New("sdcreds: host secret files need a unix system")

func readHostSecret(string) ([]byte, error)             { return nil, errNoHostFile }
func readHostSecretFile(*os.File) ([]byte, error)       { return nil, errNoHostFile }
func createHostSecret(string, [16]byte) ([]byte, error) { return nil, errNoHostFile }
