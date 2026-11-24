package safemode

import (
	"errors"
	"sync"
	"testing"
)

func TestACLReadOnlyToggle(t *testing.T) {
	var a ACL
	if a.IsReadOnly() {
		t.Fatal("zero value ACL must allow writes")
	}
	a.SetReadOnly(true)
	if !a.IsReadOnly() {
		t.Fatal("SetReadOnly(true) did not take effect")
	}
	a.SetReadOnly(false)
	if a.IsReadOnly() {
		t.Fatal("SetReadOnly(false) did not take effect")
	}
}

func TestACLGuard(t *testing.T) {
	var a ACL
	called := 0
	fn := func() error { called++; return nil }

	if err := a.Guard(fn); err != nil || called != 1 {
		t.Fatalf("writable guard: err=%v called=%d", err, called)
	}
	a.SetReadOnly(true)
	if err := a.Guard(fn); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("read-only guard error = %v, want ErrReadOnly", err)
	}
	if called != 1 {
		t.Fatalf("fn must not run in read-only mode, called=%d", called)
	}
}

func TestCheckPermission(t *testing.T) {
	var a ACL
	ops := []string{"write:profile", "write:settings", "write:proxy", "write", "read:profile"}
	for _, op := range ops {
		if err := CheckPermission(&a, op); err != nil {
			t.Fatalf("writable ACL rejected %q: %v", op, err)
		}
	}
	// A nil ACL means "no restriction".
	if err := CheckPermission(nil, "write:profile"); err != nil {
		t.Fatalf("nil ACL must allow writes: %v", err)
	}

	a.SetReadOnly(true)
	for _, op := range []string{"write:profile", "write:settings", "write:proxy", "write"} {
		if err := CheckPermission(&a, op); !errors.Is(err, ErrReadOnly) {
			t.Fatalf("read-only ACL allowed %q: %v", op, err)
		}
	}
	if err := CheckPermission(&a, "read:profile"); err != nil {
		t.Fatalf("reads must stay allowed: %v", err)
	}
}

func TestACLConcurrentAccess(t *testing.T) {
	var a ACL
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			a.SetReadOnly(true)
			a.SetReadOnly(false)
		}()
		go func() {
			defer wg.Done()
			_ = a.IsReadOnly()
			_ = CheckPermission(&a, "write:settings")
			_ = a.Guard(func() error { return nil })
		}()
	}
	wg.Wait()
}
