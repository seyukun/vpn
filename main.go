package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"wgvpm/macro"

	"github.com/pkg/taptun"
)

func main() {
	tun, err := taptun.NewTun("vpm0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[tun](%s:%d) Error: %s\n", macro.FILE__(), macro.LINE__(), err.Error())
		os.Exit(1)
	}
	defer tun.Close()
	fmt.Printf("[tun](%s:%d) %s opened\n", macro.FILE__(), macro.LINE__(), tun)
	// if err := syscall.SetNonblock(int(tun.Fd), true); err != nil {
	// 	fmt.Fprintf(os.Stderr, "[tun](%s:%d) Error: %s\n", macro.FILE__(), macro.LINE__(), err.Error())
	// 	os.Exit(1)
	// }

	addr, err := net.ResolveUDPAddr("udp", ":12345")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[udp](%s:%d) Error: %s\n", macro.FILE__(), macro.LINE__(), err.Error())
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[udp](%s:%d) Error: %s\n", macro.FILE__(), macro.LINE__(), err.Error())
		os.Exit(1)
	}
	defer conn.Close()
	// fmt.Printf("[udp](%s:%d) %s opened\n", macro.FILE__(), macro.LINE__(), conn.LocalAddr())
	// if connFd, err := conn.File(); err != nil {
	// 	fmt.Fprintf(os.Stderr, "[udp](%s:%d) Error: %s\n", macro.FILE__(), macro.LINE__(), err.Error())
	// 	os.Exit(1)
	// } else {
	// 	if err := syscall.SetNonblock(int(connFd.Fd()), true); err != nil {
	// 		fmt.Fprintf(os.Stderr, "[udp](%s:%d) Error: %s\n", macro.FILE__(), macro.LINE__(), err.Error())
	// 		os.Exit(1)
	// 	}
	// }

	var wg sync.WaitGroup
	var remote string = os.Args[1]
	remoteAddr, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[udp](%s:%d) Error: %s\n", macro.FILE__(), macro.LINE__(), err.Error())
		os.Exit(1)
	}

	for i := 0; i < 1; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				buf := make([]byte, 1500)
				if n, remoteAddr, err := conn.ReadFromUDP(buf); err != nil {
					fmt.Fprintf(os.Stderr, "[udp](%s:%d) Error: %s\n", macro.FILE__(), macro.LINE__(), err.Error())
				} else if n != 0 {
					go fmt.Printf("[udp](%s:%d) Log: recieved from %s\n", macro.FILE__(), macro.LINE__(), remoteAddr.String())
					tun.Write(buf[:n])
				} else {
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}

	for i := 0; i < 1; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				buf := make([]byte, 1500)
				if n, err := tun.Read(buf); err != nil {
					fmt.Fprintf(os.Stderr, "[tun](%s:%d) Error: %s\n", macro.FILE__(), macro.LINE__(), err.Error())
				} else if n != 0 {
					go fmt.Printf("[tun](%s:%d) Log: recieved from %s\n", macro.FILE__(), macro.LINE__(), tun)
					conn.WriteToUDP(buf[:n], remoteAddr)
				} else {
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("Shutting down...")
	wg.Wait()
	fmt.Println("All goroutines finished")
}
