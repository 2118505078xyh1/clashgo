package singleinstance

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestSecondLaunchAsksFirstToShow(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	shown := make(chan struct{}, 1)
	release, err := Try(port, func() { shown <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	if _, err := Try(port, nil); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Try error = %v, want ErrAlreadyRunning", err)
	}
	select {
	case <-shown:
	case <-time.After(2 * time.Second):
		t.Fatal("running instance was not asked to show its window")
	}
}
