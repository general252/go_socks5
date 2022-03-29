package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/general252/go_socks5"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	s := go_socks5.NewServer()
	if err := s.Start(1080); err != nil {
		log.Println(err)
	}

	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Kill, syscall.SIGINT, syscall.SIGTERM)
	<-c

	s.Stop()
}
