//go:build !((linux && !android) || (darwin && !ios))

package credential

import "os"

func privateOwnedRegular(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular()
}

func privateOwnedRegularForStateDir(info os.FileInfo, _ string) bool {
	return privateOwnedRegular(info)
}

func directoryOwnerUID(os.FileInfo) (uint32, bool) {
	return 0, false
}

func isDirectoryWritableByCurrentUser(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0o200 != 0
}

// ResolveSudoInvoker reports false on non-POSIX platforms.
func ResolveSudoInvoker() (uint32, string, bool) {
	return 0, "", false
}

func sudoInvokerUIDGID() (uint32, int, bool) {
	return 0, -1, false
}

func chownToSudoInvokerIfMatching(string, uint32, int) {}
