// Package safemode contains small helpers used to harden clashgo at startup
// and to refuse mutating operations while the app is in read-only mode.
package safemode

import "os"

// NonInteractive reports whether the process was launched without a user at
// the console (for example a CI job or an unattended service). In that case
// the app must not block on first-run dialogs.
func NonInteractive() bool {
	return envTruthy("CLASHGO_NONINTERACTIVE") || envTruthy("CI")
}

// AcceptDisclaimer reports whether the first-run disclaimer/wizard may be
// silently accepted. It shares the same signals as NonInteractive so an
// automated launch never gets stuck waiting for a click.
func AcceptDisclaimer() bool {
	return NonInteractive()
}

// envTruthy recognises the usual "enabled" spellings. os.LookupEnv is not
// needed here: an unset variable and an empty one both mean "not enabled".
func envTruthy(key string) bool {
	switch os.Getenv(key) {
	case "1", "true", "TRUE", "True", "yes", "YES", "on", "ON":
		return true
	}
	return false
}
