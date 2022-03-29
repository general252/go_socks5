package go_socks5

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
)

// server client: "golang.org/x/net/proxy" "github.com/0990/socks5/cmd/client"
type server struct {
	listenerTCP *net.TCPListener
	listenerUDP *net.UDPConn
}

func NewServer() *server {
	return &server{}
}

func (c *server) Start(port int) error {
	var err error

	// 接收代理请求、验证
	c.listenerTCP, err = net.ListenTCP("tcp4", &net.TCPAddr{
		IP:   net.IPv4zero,
		Port: port,
	})
	if err != nil {
		return err
	}

	// socks代理中的udp转发
	c.listenerUDP, err = net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: port,
	})

	// udp转发都返回这个地址, 如果是公网, 使用配置地址
	hostIp, err := GetHostIP()
	if err != nil {
		return err
	}
	udpAddr, err := NewAddrByteFromString(fmt.Sprintf("%v:%d", hostIp, port))
	if err != nil {
		return err
	}

	go func() {
		for {
			// socks代理
			conn, err := c.listenerTCP.AcceptTCP()
			if err != nil {
				log.Println(err)
				return
			}

			_ = conn.SetKeepAlive(true)
			_ = conn.SetReadBuffer(512 * 1024)
			_ = conn.SetWriteBuffer(512 * 1024)

			// 处理新连接
			go NewConnection(conn, udpAddr).Handle()
		}
	}()

	go func() {
		// 来自socks代理客户端的连接 (没有和代理的tcp connection关联, 使用单端口接收转发请求, 不容易关联tcp connection)
		var clientList sync.Map

		buffer := make([]byte, 65535)
		for {
			// 来自代理端的数据, 接收后转发给remote(数据包中包含remote地址)
			n, fromAddr, err := c.listenerUDP.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			data := buffer[:n]
			log.Println("read udp from: ", fromAddr.String())

			var cli *UdpClient
			tmpCli, found := clientList.Load(fromAddr.String())
			if !found {
				cli = &UdpClient{
					listenerUDP: c.listenerUDP,
					addr:        fromAddr,
					OnError: func(err error, c *UdpClient) {
						clientList.Delete(c.addr.String())
					},
				}

				// 连接远程
				if err = cli.Connect(data); err != nil {
					log.Println(err)
					continue
				}

				// 保存udp client
				clientList.Store(fromAddr.String(), cli)
			} else {
				cli = tmpCli.(*UdpClient)
			}

			// 转发数据
			if err = cli.Handle(data); err != nil {
				log.Println(err)
			}
		}
	}()

	return nil
}

func (c *server) Stop() {
	_ = c.listenerTCP.Close()
	_ = c.listenerUDP.Close()
}

// GetHostIP get pc local host ip address
func GetHostIP() (string, error) {
	conn, err := net.Dial("udp", "192.192.192.192:80")
	if err != nil {
		return "127.0.0.1", err
	}
	defer func() {
		_ = conn.Close()
	}()

	var ip = strings.Split(conn.LocalAddr().String(), ":")[0]
	return ip, nil
}
