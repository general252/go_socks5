package go_socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type HandShake struct {
	header []byte
	body   []byte

	ip     net.IP
	port   int
	domain string
}

func (c *HandShake) Address() string {
	var host = c.domain
	if len(c.ip) > 0 {
		host = c.ip.String()
	}

	return fmt.Sprintf("%v:%v", host, c.port)
}

type UdpClient struct {
	listenerUDP *net.UDPConn // udp转发服务的连接, 用于回复数据
	addr        *net.UDPAddr // socks代理客户端的地址
	h           *HandShake

	remoteConn *net.UDPConn // 连接远程

	OnError func(err error, cli *UdpClient)
}

func (c *UdpClient) Connect(buf []byte) error {
	h, err := c.handshake(buf)
	if err != nil {
		return err
	}

	c.h = h

	// 连接远程
	if tmpConn, err := net.DialTimeout("udp", h.Address(), time.Second*10); err != nil {
		log.Printf("connect fail %v %v", h.Address(), err)
		return err
	} else {
		var ok bool
		c.remoteConn, ok = tmpConn.(*net.UDPConn)
		if !ok {
			return io.EOF
		}
	}

	go func() {
		defer func() {
			_ = c.remoteConn.Close()

			log.Printf("dial close %v %v", c.remoteConn.LocalAddr(), c.remoteConn.RemoteAddr())
		}()

		log.Printf("new dial %v %v", c.remoteConn.LocalAddr(), c.remoteConn.RemoteAddr())

		var handleError = func(err error) {
			if c.OnError != nil {
				c.OnError(err, c)
			}
		}

		// 读取远程数据
		buffer := make([]byte, 65535)
		for {
			n, _, err := c.remoteConn.ReadFromUDP(buffer)
			if err != nil {
				handleError(err)
				return
			}

			body := append(h.header, buffer[:n]...)

			// 转发给socks客户端
			_, err = c.listenerUDP.WriteToUDP(body, c.addr)
			if err != nil {
				handleError(err)
				return
			}
		}
	}()

	return nil
}

func (c *UdpClient) Handle(buf []byte) error {
	h, err := c.handshake(buf)
	if err != nil {
		return err
	}

	// 转发给远程
	_, err = c.remoteConn.Write(h.body)

	return err
}

func (c *UdpClient) handshake(buf []byte) (*HandShake, error) {
	var (
		rsv  [2]byte
		flag byte
	)

	if len(buf) < 4 || !bytes.Equal(buf[:2], rsv[:]) || buf[2] != flag {
		return nil, errors.New("fail")
	}

	var header, body []byte
	var aTyp = buf[3]

	var (
		ip     net.IP
		port   int
		domain string
	)

	switch aTyp {
	case ATypIPv4:
		if len(buf) < 10 {
			return nil, errors.New("header is too short for IPv4")
		}
		ip = net.IPv4(buf[4], buf[5], buf[6], buf[7])
		port = int(binary.BigEndian.Uint16(buf[8:10]))
		body = buf[10:]
		header = buf[:10]
	case ATypDomain:
		if len(buf) < 5 {
			return nil, errors.New("header is too short for domain")
		}
		domainLen := int(buf[4])
		if domainLen <= 0 || len(buf) < 5+domainLen+2 {
			return nil, errors.New("header is too short for domain")
		}
		domain = string(buf[5 : 5+domainLen])
		if ipAddr, err := net.ResolveIPAddr("ip", domain); err != nil {
			// return nil, errors.New("can't resolve domain:" + domain)
		} else {
			ip = ipAddr.IP
		}
		port = int(binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2]))
		body = buf[5+domainLen+2:]
		header = buf[:5+domainLen+2]
	case ATypIPv6:
		if len(buf) < 22 {
			return nil, errors.New("header is too short for IPv6")
		}
		ip = net.ParseIP(string(buf[4:20]))
		port = int(binary.BigEndian.Uint16(buf[20:22]))
		body = buf[22:]
		header = buf[:22]
	default:
		return nil, errors.New("unsupported aTyp")
	}

	h := make([]byte, len(header))
	copy(h, header)

	return &HandShake{
		header: h,
		body:   body,
		ip:     ip,
		port:   port,
		domain: domain,
	}, nil
}
