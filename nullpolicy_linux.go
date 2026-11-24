//go:build linux

package sdcreds

import "os"

// systemNullPolicy ports the state queries of check_null_key_policy:
//   - policy: /proc/cmdline (proc_cmdline_get_key);
//   - SecureBoot: the SecureBoot EFI variable, 4 attribute bytes then one data
//     byte (efivars.c:371-386); absent means off;
//   - TPM2 known to the firmware (efi-api.c:601-): an EFI boot and the ACPI
//     TPM2 table, or a TPM 2.0 event log. The loader's LoaderTpm2ActivePcrBanks
//     variable is not consulted;
//   - first boot: $SYSTEMD_FIRST_BOOT or /run/systemd/first-boot (initrd-util.c:42-64).
func systemNullPolicy() func() error {
	policy := PolicyFromCmdline(readFileString("/proc/cmdline"))
	efi := exists("/sys/firmware/efi")
	secure := false
	if b, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"); err == nil && len(b) == 5 {
		secure = b[4] != 0
	}
	tpm2 := efi && (exists("/sys/firmware/acpi/tables/TPM2") ||
		(exists("/sys/kernel/security/tpm0/binary_bios_measurements") &&
			trimNL(readFileString("/sys/class/tpm/tpm0/tpm_version_major")) == "2"))
	first := exists("/run/systemd/first-boot")
	if v, ok := os.LookupEnv("SYSTEMD_FIRST_BOOT"); ok {
		first = !envFalseValue(v)
	}
	return NullPolicyFor(policy, first, tpm2, secure)
}

func readFileString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

func envFalseValue(v string) bool {
	switch v {
	case "0", "no", "false", "off", "n", "f":
		return true
	}
	return false
}
