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
* A credential sealed with the null key has no secrecy: `sdcreds decrypt`
  refuses it on every machine unless `--allow-null` is given (systemd instead
  consults the TPM2 and SecureBoot state; that library policy,
  `SystemNullPolicy`, is not used by the CLI).
* `SDCREDS_MACHINE_ID_FILE` (`encrypt`, `decrypt`, `setup`) points at another machine
  id file. `s6-run` ignores it and `SYSTEMD_CREDENTIAL_SECRET`: its key comes from
  the default files, or from `--secret` and `--machine-id-file`, which must name
  regular files owned by root that group and others cannot write.
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
`CREDENTIALS_DIRECTORY`, then starts the service in a child that drops privileges
(`no_new_privs`, an empty capability set; see `--keep-cap` below) and waits for it. `s6-run` keeps its
privileges and the mount, so a program that cannot be executed (not an
executable file, a `noexec` file system) is reported by the child's exec and the
credentials are taken away before `s6-run` fails; the same happens when the
service ends. `s6-run` is still the process that s6 supervises: it forwards
`TERM`, `INT`, `HUP`, `QUIT`, `USR1`, `USR2`, `ALRM` and `CONT` to the service,
exits with its status (128 plus the signal number if a signal killed it), hands
on the descriptors it was given (a notification pipe, for one), and the service
is killed if `s6-run` dies. The mount lives in a private namespace by default
(`--unshare=false` turns that off), so it disappears with the service. The command is looked up before
anything is mounted, and so is whether the service user may execute it. The
base directory, when `s6-run` creates it, is made 0755 whatever the umask.
Every mount is named `sdcreds`, and `s6-finish` (like `s6-run` before it mounts)
detaches only a mount of that name. A credential sealed with the null key is refused unless
`--allow-null` is given, and one that carries no name is always refused. `sdcreds s6-finish --service=web` unmounts lazily and removes the
directory; it is idempotent. At most 1024 credentials and 16 MiB per service.
Linux only; elsewhere the commands report `ErrUnsupported`.

### Keeping a capability: `--keep-cap`

A service that needs one capability (a VPN server that configures a tun device
needs `CAP_NET_ADMIN`) runs with `sdcreds s6-run --keep-cap=CAP_NET_ADMIN ...`.
The flag is repeatable and comma-separated (`--keep-cap=CAP_NET_ADMIN,CAP_NET_RAW`
or one flag each) and has **no default**: without it the service runs exactly as
before, with every capability set empty.

It is an **allowlist**, and only these seven capabilities can be kept, each one
because it is not root-equivalent and gives no way to read or write the credential
tmpfs (that needs `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_FOWNER`, `CAP_CHOWN`
or `CAP_SYS_ADMIN`) or to signal the root `s6-run` (`CAP_KILL`, `CAP_SYS_PTRACE`,
`CAP_SETUID`):

| capability | what it allows |
| --- | --- |
| `CAP_NET_ADMIN` | interfaces, routes, firewall, tun devices |
| `CAP_NET_BIND_SERVICE` | ports below 1024 |
| `CAP_NET_RAW` | raw and packet sockets |
| `CAP_NET_BROADCAST` | broadcast and multicast sockets |
| `CAP_IPC_LOCK` | `mlock`, so key material stays out of swap |
| `CAP_WAKE_ALARM` | timers that wake the system |
| `CAP_BLOCK_SUSPEND` | holding the system awake |

Any other capability that exists is an error that names the allowlist, and so is
a name that is not a capability; both are reported before the key is read,
anything is decrypted or anything is mounted.

The service then has, in its bounding, permitted, inheritable, effective and
ambient sets, exactly the kept capabilities and nothing else. `no_new_privs`
stays on, so a set-user-id or file-capability program it runs gains nothing, and
the securebits `SECBIT_NOROOT` and `SECBIT_NO_SETUID_FIXUP` are set and locked
(`SECBIT_NOROOT_LOCKED`, `SECBIT_NO_SETUID_FIXUP_LOCKED`): the service cannot
unlock them, and reaching uid 0 would give it nothing. The order is the one of
capabilities(7) and prctl(2): `no_new_privs`, the bounding set cut to the kept
set, the inheritable set, the securebits, then in the child `SECBIT_KEEP_CAPS`
across the change of uid, and the ambient raise. `s6-run`'s own privileges are
unchanged; the interop test reads `/proc/self/status` of the service and of
`s6-run` to check both.

### Security notes

* The key files named by `--secret` and `--machine-id-file` must be root-owned
  and not writable by group or others, and so must every directory above them up
  to `/` (a symbolic link in the path is resolved, and the directories it leads
  to are judged the same way). The key file is opened once, without following a
  final link: the descriptor that was judged is the one the key is read from, and
  the path is never opened again by name. The key is wiped from the memory of
  `s6-run` when it is done with the credentials.
* Only the child takes the identity of the service; `s6-run` and all its threads
  stay root. `s6-run` started inside a chroot starts the service in that chroot.
* The service has no capability unless `--keep-cap` names one of the seven of the
  allowlist above. A kept capability is a privilege of the service and the
  operator's decision; `CAP_NET_ADMIN`, for one, lets the service change the
  network of its namespace (so run such a service in its own network namespace if
  that matters), and `CAP_NET_RAW` lets it read and forge packets there. None
  adds any access to the credential file system (read-only, and the service user
  already owns it) or any way to signal or ptrace `s6-run`.
* A `TERM` (or any forwarded signal) is held by `s6-run` from before the first
  mount until the credentials are gone: one that comes while they are staged
  stops the run, with the status of a process killed by it, before the service
  starts and after the staging mount is detached and removed; one that comes
  while `s6-run` takes the credentials away does not end it before the unmount.
  `sdcreds s6-finish` also detaches and removes a staging mount (named `sdcreds`)
  that an earlier run left under the base directory; it never touches a staging
  directory of another service or a mount of another name. The plaintext is wiped from the memory
  of `s6-run` as soon as it is in the file system, before the service starts.
* The AES key derived from the host key (and the unscoped hash a scoped key is
  derived from) is wiped as soon as the cipher is built. `crypto/aes` keeps an
  expanded key schedule inside the cipher, and the SHA-256 and HMAC states hold
  key material while they live; Go gives no way to wipe either, so a copy of
  the key stays in memory until the garbage collector reuses it.
* With `--unshare=false` the mount lives in the namespace of the host: a `SIGKILL`
  of `s6-run` (which cannot be caught) leaves the mount in place, and it stays
  until `sdcreds s6-finish` runs (put it in the finish script of the service). The
  default, a private namespace, has no such leftover.

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
* `mutsweep` catches every guard of `s6`, `cmd/sdcreds` and `internal/perf` by an
  assertion. `s6/ops_linux.go` and `s6/start_linux.go` are excluded from a macOS
  sweep (build tags) and are covered by the root integration tests in the interop
  image (bad executable, `noexec`, signals, exit status, parent death).

## Licence

See `LICENSE`.
