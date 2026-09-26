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
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap the child; we don't wait for the browser to exit
	return nil
}

// OpenBrowser opens url in the system browser. Tests replace it.
var OpenBrowser = defaultOpenBrowser
