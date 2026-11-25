package main

import (
	"github.com/go-authn/sdcreds/delivery"
	"github.com/go-authn/sdcreds/s6"
)

// readTrustedSource is the sealed credentials of an s6-run source directory,
// read through the trust walk of the `run` path (delivery.ReadSourceTrusted):
// a directory or file that someone other than root could have changed is refused
// before anything is decrypted.
func readTrustedSource(dir string) ([]s6.Sealed, error) {
	creds, err := delivery.ReadSourceTrusted(dir, trustedUID, ancestorsFrom)
	if err != nil {
		return nil, err
	}
	out := make([]s6.Sealed, len(creds))
	for i, c := range creds {
		out[i] = s6.Sealed{Name: c.Name, Data: c.Sealed}
	}
	return out, nil
}
