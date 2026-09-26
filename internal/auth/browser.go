package auth

import (
	"os/exec"
	"runtime"
)

// defaultOpenBrowser opens url in the system's default browser.
func defaultOpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// OpenBrowser opens url in the system browser. Tests replace it.
var OpenBrowser = defaultOpenBrowser
