package main

import (
	"fmt"
	"log"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	target := fmt.Sprintf("socks5://%v:%v", "127.0.0.1", 1080) // "socks5://user:password@host:port"
	targetURL, err := url.Parse(target)
	if err != nil {
		log.Panicln(err)
	}

	pxy, err := proxy.FromURL(targetURL, nil)
	if err != nil {
		log.Panicln(err)
	}

	// 不支持udp
	conn, err := pxy.Dial("tcp4", "192.168.6.80:10000")
	if err != nil {
		log.Panicln(err)
	} else {
		defer func() {
			_ = conn.Close()
		}()
	}

	for i := 0; i < 5; i++ {
		time.Sleep(time.Second)
		if _, err = conn.Write([]byte(time.Now().Format(time.RFC3339))); err != nil {
			log.Panicln(err)
		}
	}
}
