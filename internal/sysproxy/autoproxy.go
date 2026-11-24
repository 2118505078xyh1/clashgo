package sysproxy

// AutoProxy manages the OS "automatic proxy configuration" (PAC URL) setting.
type AutoProxy struct {
	Enable bool   `json:"enable"`
	URL    string `json:"url"`
}

// SetAutoProxy enables or disables PAC auto-configuration.
func SetAutoProxy(enable bool, pacURL string) error {
	return setAutoOS(enable, pacURL)
}

// GetAutoProxy reads the current PAC setting.
func GetAutoProxy() (*AutoProxy, error) {
	return getAutoOS()
}
