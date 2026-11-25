//go:build openbsd

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/delivery"
)

// hostKeyPath is the OpenBSD host key: root-owned, mode exactly 0600.
const hostKeyPath = "/etc/sdcreds/host.key"

// hwUUID is the machine id of OpenBSD, `sysctl hw.uuid`; a seam for the tests.
var hwUUID = func() ([16]byte, error) {
	s, err := unix.Sysctl("hw.uuid")
	if err != nil {
		return [16]byte{}, fmt.Errorf("sysctl hw.uuid: %w", err)
	}
	return parseUUID(s)
}

func init() { runFlow = openbsdFlow }

// openbsdHostKey reads the host key from one descriptor that was judged: the
// path walk (root-owned ancestors, no link), then the exact mode 0600.
func openbsdHostKey(secret, machineIDFile string) ([]byte, error) {
	if secret == "" {
		secret = hostKeyPath
	}
	f, err := openTrusted(secret)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	defer f.Close()
	var mid [16]byte
	if machineIDFile != "" {
		mid, err = readTrustedMachineID(machineIDFile)
	} else {
		mid, err = hwUUID()
	}
	if err != nil {
		return nil, err
	}
	return sdcreds.HostKeyFromFileMode(f, mid, 0o600)
}

// openbsdFlow is `run` once every refusal passed.
func openbsdFlow(cmd *cobra.Command, p *runPlan) error {
	hardenProcess()
	self, err := trustedSelf()
	if err != nil {
		return &refusal{err}
	}
	// The stub is this binary run as the target: it must be able to start.
	if err := canExecAs(self, p.uid, p.gid, p.groups); err != nil {
		return &refusal{fmt.Errorf("%w: sdcreds itself: %v", errNotExecutable, err)}
	}
	// The limits of --class are read before anything is mounted or decrypted: a
	// class that cannot be read refuses the run.
	limits, err := classLimitSpec(p.class)
	if err != nil {
		return &refusal{err}
	}
	if err := delivery.EnsureBase(p.base); err != nil {
		return err
	}
	lock, err := delivery.AcquireLock(p.base, p.service)
	if errors.Is(err, delivery.ErrBusy) {
		return &refusal{err}
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	if sw, err := delivery.SweepService(p.base, p.service); err != nil {
		return err
	} else {
		for _, s := range sw {
			fmt.Fprintf(cmd.ErrOrStderr(), "sdcreds run: swept a leftover %s (mounted: %v)\n", s.Dir, s.Mounted)
		}
	}

	key, err := openbsdHostKey(p.secret, p.machineIDFile)
	if err != nil {
		return &refusal{err}
	}
	defer clear(key)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	d, err := delivery.Prepare(ctx, delivery.Config{
		Base: p.base, Name: p.service, UID: p.uid, GID: p.gid, Groups: p.groups, Creds: p.creds,
		Lock: lock, Executable: self,
		Decrypt: decrypter(sdcreds.StaticHostKey(key), p.allowNull),
	})
	stop()
	clear(key)
	if err != nil {
		return err
	}
	defer d.Release()

	code, err := runStub(cmd, p, d, self, limits)
	if err != nil {
		// Whatever the program started must not outlive the failure.
		if kerr := d.KillTarget(); kerr != nil {
			err = errors.Join(err, kerr)
		}
		return err
	}
	if err := d.Release(); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "sdcreds run: release: %v\n", err)
	}
	lock.Close()
	osExit(code)
	return nil
}

// forwarded are the signals handed on to the program.
var forwarded = []os.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2}

// runStub starts the exec stub as the target user in a process group of its
// own, has the helper guard that group, releases the stub to exec the program,
// and waits for it. Killing this process kills the group (the helper does it).
func runStub(cmd *cobra.Command, p *runPlan, d *delivery.Delivery, self, limits string) (int, error) {
	gr, gw, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer gw.Close()
	groups := make([]uint32, len(p.groups))
	for i, g := range p.groups {
		groups[i] = uint32(g)
	}
	c := exec.Command(self, append([]string{stubCommand, "--", p.program}, p.args...)...)
	c.Env = stubEnv(os.Environ(), d.Dir)
	if limits != "" {
		c.Env = append(c.Env, rlimitEnv+"="+limits)
	}
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.ExtraFiles = []*os.File{gr}
	c.SysProcAttr = &syscall.SysProcAttr{
		Setsid:     true,
		Credential: &syscall.Credential{Uid: uint32(p.uid), Gid: uint32(p.gid), Groups: groups},
	}
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, forwarded...)
	defer signal.Stop(sigs)
	if err := c.Start(); err != nil {
		gr.Close()
		return 0, err
	}
	gr.Close()
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	if err := d.GuardGroup(c.Process.Pid); err != nil {
		_ = d.KillTarget()
		<-done
		return 0, err
	}
	if _, err := gw.Write([]byte{goByte}); err != nil {
		_ = d.KillTarget()
		<-done
		return 0, err
	}
	gw.Close()
	lost := d.Lost()
	for {
		select {
		case s := <-sigs:
			_ = c.Process.Signal(s)
		case <-lost:
			// The helper is gone: nothing guards the mount or the program any
			// more. Kill every process of the target and fail.
			fmt.Fprintln(cmd.ErrOrStderr(), "sdcreds run: delivery lost: the credential mount is gone; killing the program")
			kerr := d.KillTarget()
			<-done
			return 0, errors.Join(errDeliveryLost, kerr)
		case err := <-done:
			var ee *exec.ExitError
			if err != nil && !errors.As(err, &ee) {
				return 0, err
			}
			return exitCode(c.ProcessState), nil
		}
	}
}

// errDeliveryLost is the end of a run whose helper went away.
var errDeliveryLost = errors.New("the credential delivery was lost")

// trustedSelf is the path of this executable, resolved, and judged like the key
// file: root-owned, not writable by group or others, every directory above it
// too. The helper and the stub run from it, as other users, so it must not be
// something that user could have replaced.
func trustedSelf() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	if p, err = filepath.EvalSymlinks(p); err != nil {
		return "", err
	}
	f, err := openTrusted(p)
	if err != nil {
		return "", fmt.Errorf("sdcreds executable: %w", err)
	}
	f.Close()
	return filepath.Clean(p), nil
}

func exitCode(ps *os.ProcessState) int {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}

// readClassFile reads a login.conf file judged like the key file (root-owned,
// not writable by group or others, every directory above it too); a file that
// does not exist is reported as such, any other failure is an error.
func readClassFile(path string) (string, bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	f, err := openTrusted(path)
	if err != nil {
		return "", false, fmt.Errorf("login class file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, loginConfMax+1))
	if err != nil {
		return "", false, err
	}
	if len(data) > loginConfMax {
		return "", false, fmt.Errorf("%s is longer than %d bytes", path, loginConfMax)
	}
	return string(data), true, nil
}

// classLimitSpec is the encoded limits of --class, or "" without one.
func classLimitSpec(class string) (string, error) {
	if class == "" {
		return "", nil
	}
	ls, err := LoadClassLimits(class, readClassFile)
	if err != nil {
		return "", err
	}
	return EncodeLimits(ls), nil
}
