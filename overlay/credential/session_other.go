//go:build !((linux && !android) || (darwin && !ios))

package credential

import "os"

func privateOwnedRegular(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular()
}
