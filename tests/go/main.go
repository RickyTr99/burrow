// Go: trapped syscalls from many goroutines, on Go's small stacks.
//
// Built by tools/burrow-test.sh when a Go toolchain is there (GOOS=linux
// GOARCH=arm64 go build), run by run.sh as go/burrowtest.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var fails int

func ok(cond bool, what string) {
	if cond {
		fmt.Println("ok   " + what)
	} else {
		fmt.Println("FAIL " + what)
		fails++
	}
}

func main() {
	d, err := os.MkdirTemp("", "burrow-go.")
	ok(err == nil, "MkdirTemp")
	f := filepath.Join(d, "f")
	ok(os.WriteFile(f, []byte("data"), 0o644) == nil, "WriteFile")
	ok(os.Symlink(f, filepath.Join(d, "abs")) == nil, "Symlink")

	// Goroutines on small stacks, all trapping at once
	uid := os.Getuid()
	var wg sync.WaitGroup
	var mu sync.Mutex
	bad := 0
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				b, err := os.ReadFile(filepath.Join(d, "abs"))
				_, serr := os.Stat("/usr/lib")
				if err != nil || string(b) != "data" || serr != nil || os.Getuid() != uid {
					mu.Lock()
					bad++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	ok(bad == 0, fmt.Sprintf("64 goroutines x 200 (%d bad)", bad))

	link, err := os.Readlink(filepath.Join(d, "abs"))
	ok(err == nil && link == f, "Readlink")
	exe, err := os.Executable()
	ok(err == nil && filepath.Base(exe) == "burrowtest", "Executable: "+exe)
	out, err := exec.Command("sh", "-c", "echo $0", "go").Output()
	ok(err == nil && string(out) == "go\n", "exec")

	// Signals: Go's handlers run on its gsignal stacks
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR1)
	syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	select {
	case <-c:
		ok(true, "a signal")
	case <-time.After(5 * time.Second):
		ok(false, "a signal")
	}

	os.RemoveAll(d)
	if fails > 0 {
		os.Exit(1)
	}
}
