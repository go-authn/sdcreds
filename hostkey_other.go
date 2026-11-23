//go:build !unix

package sdcreds

import "errors"

var errNoHostFile = errors.New("sdcreds: host secret files need a unix system")

func readHostSecret(string) ([]byte, error)             { return nil, errNoHostFile }
func createHostSecret(string, [16]byte) ([]byte, error) { return nil, errNoHostFile }
