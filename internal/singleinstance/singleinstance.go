// Package singleinstance ensures only one clashgo process runs at a time.
// A second launch asks the running instance to show its window instead of
// silently exiting, so double-clicking the exe always brings up the UI.
package singleinstance

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const showMessage = "SHOW\n"

var (
	// ErrAlreadyRunning is returned to a second instance after it has asked
	// the running instance to show its window.
	ErrAlreadyRunning = errors.New("another clashgo instance is running")

	mu   sync.Mutex
	ln   net.Listener
	held bool
)

// Try acquires the single-instance lock. On success it starts listening for
// second-launch notifications and calls onShow when one arrives. The returned
// function releases the lock.
func Try(port int, onShow func()) (func(), error) {
	mu.Lock()
	defer mu.Unlock()
	if held {
		_ = notify(port)
		return nil, ErrAlreadyRunning
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		// The port is already taken. Most likely it is the running ClashGo;
		// ask it to raise its window and report a benign duplicate launch.
		_ = notify(port)
		return nil, fmt.Errorf("%w: %v", ErrAlreadyRunning, err)
	}
	ln = l
	held = true
	go accept(l, onShow)
	return release, nil
}

func release() {
	mu.Lock()
	defer mu.Unlock()
	if ln != nil {
		_ = ln.Close()
		ln = nil
	}
	held = false
}

func accept(l net.Listener, onShow func()) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			line, _ := bufio.NewReader(c).ReadString('\n')
			if line == showMessage && onShow != nil {
				onShow()
			}
		}(c)
	}
}

// notify asks the instance holding the lock to show its window.
func notify(port int) error {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = c.Write([]byte(showMessage))
	return err
}
