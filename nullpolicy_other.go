//go:build !linux

package sdcreds

// systemNullPolicy accepts: there is no EFI or TPM state to read off Linux.
func systemNullPolicy() func() error { return func() error { return nil } }
