//go:build openbsd && (386 || arm)

package delivery

// 32-bit OpenBSD is refused, at build time and on purpose. The mount arguments
// (mfsArgs, mfsArgsSize 144) and the kernel structures read by kinfo.go are the
// LP64 layout of amd64 and arm64; nothing here has been checked against the
// ILP32 headers of i386 or armv7, so a binary built for them would hand the
// kernel a layout nobody verified.
//
// The compile error below names the reason:
//
//	undefined: sdcreds_does_not_build_on_32bit_OpenBSD__mfsArgsSize_144_and_the_mount_layout_are_LP64_only
var _ = sdcreds_does_not_build_on_32bit_OpenBSD__mfsArgsSize_144_and_the_mount_layout_are_LP64_only
