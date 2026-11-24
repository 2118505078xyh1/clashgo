package ui

// ConfigFile and RuntimeFile are injected by main with resolved paths.
var ConfigFile, RuntimeFile string

func configPath() string  { return ConfigFile }
func runtimePath() string { return RuntimeFile }
