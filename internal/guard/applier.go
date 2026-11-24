package guard

// ApplierFunc adapts plain functions into an Applier.
type ApplierFunc struct {
	GetFn func() (bool, string, string, error)
	SetFn func(bool, string, string) error
}

func (a ApplierFunc) Get() (bool, string, string, error) { return a.GetFn() }
func (a ApplierFunc) Set(enable bool, server, bypass string) error {
	return a.SetFn(enable, server, bypass)
}
