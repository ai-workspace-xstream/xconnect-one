//go:build !((linux && !android) || (darwin && !ios))

package credential

import "os"

func privateOwnedRegular(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular()
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
