# sdcreds

Read and write the [systemd credential](https://systemd.io/CREDENTIALS/) format
(`systemd-creds encrypt` / `decrypt`) from Go, with a command line and a helper
that gives an s6-supervised service the same `$CREDENTIALS_DIRECTORY` that
`LoadCredentialEncrypted=` gives a systemd unit.

Supported keys: **null**, **host** (`/var/lib/systemd/credential.secret`) and
**host-scoped** (`--uid`/`--user`). TPM2 and public-key credentials are
recognised and refused with `*UnsupportedModeError`; nothing is guessed.

```sh
go install github.com/go-authn/sdcreds/cmd/sdcreds@latest
sdcreds setup                                  # create the host secret if missing
sdcreds encrypt --name=db-password plain.txt db-password.cred
sdcreds decrypt db-password.cred -             # the name must match the file name
```

```go
host := sdcreds.HostKeyFile{} // $SYSTEMD_CREDENTIAL_SECRET or the default path
blob, err := sdcreds.Encrypt(secret, sdcreds.EncryptOptions{Key: sdcreds.IDHost, HostKey: host, Name: "db-password"})
text := sdcreds.Armor(blob, sdcreds.ArmorWidth) // what systemd-creds prints
raw, _ := sdcreds.Unarmor([]byte(text))
plain, md, err := sdcreds.Decrypt(raw, sdcreds.DecryptOptions{HostKey: host, Name: &name})
```

## Interoperability

Both directions are tested against the real `systemd-creds` **262.2**, built
from the `v262.2` tag in `docker/Dockerfile` (no distribution package).

* `testdata/systemd-v262.2` holds 44 credentials written by systemd-creds
  (null, host and host-scoped; with and without a name; no, past and future
  not-after; 0 B, 1 B and 64 KiB payloads; five tampered variants), and
  `manifest.json` records what systemd-creds itself answered for each of 272
  decryption attempts (right and wrong name, before and after not-after, with
  and without `--uid`). The library gives the same answer, with the same
  class of error, for every one.
* With a fixed IV, `Encrypt` reproduces systemd's bytes exactly.
* In the container, `systemd-creds decrypt` opens what `Encrypt` wrote, and the
  command line passes the same round trip in both directions.

```sh
docker build -t sdcreds-interop docker
docker run --rm --privileged -e SDCREDS_REQUIRE_SYSTEMD=1 -e SDCREDS_S6_INTEGRATION=1 \
  -v "$PWD":/src/sdcreds -w /src/sdcreds sdcreds-interop \
  sh -c 'echo 0123456789abcdef0123456789abcdef > /etc/machine-id && go test -count=1 ./...'
docker run --rm -v "$PWD":/src/sdcreds -w /src/sdcreds sdcreds-interop go run ./internal/genvectors   # regenerate
```

Without `SDCREDS_REQUIRE_SYSTEMD=1` the tests that need the binary are skipped;
CI sets it, so an absent binary is a failure there.

### What the format is, from the source

* `block_size` is 1 for AES-GCM (`creds-util.c:1107`, checked when reading at `:1594`).
* The host secret starts with the *app-specific* machine id: HMAC-SHA256 with
  the machine id as key and the application id as message, the first 16 bytes,
  with the version-4 UUID bits set (`sd-id128.c:340-355`, `id128-util.c:211-222`).
  The generator checks this prefix against the binary's own `setup`.

### Deviations from systemd

* A host secret whose machine id does not match is **refused** (`ErrHostKeyMachine`);
  systemd removes it.
* `--with-key=auto` means `host`: there is no TPM2 here.
* The null-key policy looks for a TPM2 as systemd does, minus
  `LoaderTpm2ActivePcrBanks`.
* `SDCREDS_MACHINE_ID_FILE` (command line only) points at another machine id file.
* A variable IV size is accepted when reading, as in systemd; this library
  always writes 12 bytes.
* The secret is opened without following a final symlink, and must be a regular
  file with one link and mode `0400`, as systemd requires.

## s6

`sdcreds s6-run --service=web --user=svc --source=/etc/creds -- /usr/bin/web`
decrypts every file of `--source` **before** mounting anything, mounts a
per-service `tmpfs` (`nodev,noexec,nosuid,nosymfollow,noswap`, mode 0700, size and
inode count bounded; `ramfs` if the kernel lacks those options), writes the
plaintext 0400 owned by the service user, remounts it read-only, sets
`CREDENTIALS_DIRECTORY`, drops privileges and execs. Any failure undoes the
mount. `--unshare` puts the mount in a private namespace, so it disappears with
the service. `sdcreds s6-finish --service=web` unmounts lazily and removes the
directory; it is idempotent. At most 1024 credentials and 16 MiB per service.
Linux only; elsewhere the commands report `ErrUnsupported`.

## Safety

Every length is checked before it is used, before anything is allocated, and
on both sides of its bound; credentials are limited to 1 MiB (as systemd) and
the host secret to 16 MiB. The parsers (`FuzzParse`, `FuzzDecrypt`,
`FuzzRoundTrip`, `FuzzUnarmor`) are fuzzed in CI with the corpus in
`testdata/fuzz`, `govulncheck` runs in CI, and the tests were swept with
`mutsweep`: a deleted guard fails an assertion, it does not just crash.

## Performance

`go run ./internal/perf -ours ./sdcreds -theirs systemd-creds` runs both command
lines on the same payloads, interleaved round by round, and refuses to measure
when the 1-minute load is above 8. **No table yet:** the build machine's load
was 24 to 60 when this was written, so the measurement is deferred rather than
published unreliable (an open item, not a result). Run it in the interop image
with `--cpus=1` against `systemd-creds` once the machine is quiet, and paste the
table here.

## Test notes

* The interop vectors use 0 B, 1 B and 64 KiB payloads (a 1 MiB payload made
  1.4 MiB blobs, too large to commit). The 1 MiB boundary is covered by the
  library tests (`TestEncryptedMaxBoundary` and the bound tests in `lib_test.go`)
  only, not by interop vectors.
* `mutsweep` leaves two guards that no test can tell apart from the code under
  them: `cmd/sdcreds/main.go` `HostSecretPath` error in `setup` (the next call
  re-reads the same variable and fails identically) and the `WriteFile` error for
  the payload in `internal/perf`. `s6/ops_linux.go` is swept only on Linux and is
  covered by the root integration test.

## Licence

See `LICENSE`.
