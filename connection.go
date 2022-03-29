package go_socks5

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

type connection struct {
	UserName, Password string
	conn               *net.TCPConn
	udpAddr            AddrByte
}

func NewConnection(tcpConn *net.TCPConn, udpAddr AddrByte) *connection {
	return &connection{
		conn:    tcpConn,
		udpAddr: udpAddr,
	}
}

func (c *connection) Handle() {
	defer func() {
		_ = c.conn.Close()
		log.Printf("close connection. %v %v", c.conn.LocalAddr(), c.conn.RemoteAddr())
	}()

	log.Printf("new connection. %v %v", c.conn.LocalAddr(), c.conn.RemoteAddr())

	// 认证方法
	method, err := c.selectAuthMethod()
	if err != nil {
		log.Println(err)
		return
	}

	// 认证
	if err = c.checkAuthMethod(method); err != nil {
		log.Println(err)
		return
	}

	// 请求建立连接
	req, err := NewRequestFrom(c.conn)
	if err != nil {
		log.Println(err)
		return
	}

	switch req.Cmd {
	case CmdConnect: // tcp
		c.handleTCP(req)
	case CmdUdpAssociate: // udp
		c.handleUDP(req)
	case CmdBind:
		_, _ = c.conn.Write(NewReply(RepCmdNotSupported, nil).ToBytes())
	default:
		log.Println("error cmd ", req.Cmd)
		return
	}
}

func (c *connection) handleTCP(req *Request) {
	targetAddr := req.Address()

	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		msg := err.Error()
		var rep byte = RepHostUnreachable
		if strings.Contains(msg, "refused") {
			rep = RepConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			rep = RepNetworkUnreachable
		}

		_, _ = c.conn.Write(NewReply(rep, nil).ToBytes())
		log.Printf("connect to %v failed", req.Address())
		return
	}

	defer func() {
		_ = targetConn.Close()
	}()

	// 本地地址
	bAddr, err := NewAddrByteFromString(targetConn.LocalAddr().(*net.TCPAddr).String())
	if err != nil {
		_, _ = c.conn.Write(NewReply(RepServerFailure, nil).ToBytes())

		log.Println(err)
		return
	}

	if _, err = c.conn.Write(NewReply(RepSuccess, bAddr).ToBytes()); err != nil {
		log.Println(err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()

		_, _ = io.Copy(c.conn, targetConn)
	}()

	go func() {
		defer wg.Done()

		_, _ = io.Copy(targetConn, c.conn)
	}()

	wg.Wait()
}

func (c *connection) handleUDP(req *Request) {
	_ = req.Address()
	if _, err := c.conn.Write(NewReply(RepSuccess, c.udpAddr).ToBytes()); err != nil {
		log.Println(err)
		return
	}

	buffer := make([]byte, 128)
	for {
		_, err := c.conn.Read(buffer)
		if err != nil {
			break
		}
	}
}

func (c *connection) selectAuthMethod() (MethodType, error) {
	req, err := NewMethodSelectReqFrom(c.conn)
	if err != nil {
		return MethodNoAcceptable, err
	}

	if req.Ver != SocksVersion {
		return MethodNoAcceptable, ErrSocksVersion
	}

	var method = MethodNoAuth
	if c.UserName != "" && c.Password != "" {
		method = MethodUserPass
	}

	var exist bool
	for _, v := range req.Methods {
		if byte(method) == v {
			exist = true
			break
		}
	}

	if !exist {
		method = MethodNoAcceptable
	}

	res := NewMethodSelectReply(method)
	if _, err := c.conn.Write(res.ToBytes()); err != nil {
		return MethodNoAcceptable, err
	}

	if method == MethodNoAcceptable {
		return MethodNoAcceptable, ErrMethodNoAcceptable
	}

	return method, nil
}

func (c *connection) checkAuthMethod(method MethodType) error {
	switch method {
	case MethodNoAuth:
		return nil
	case MethodUserPass:
		req, err := NewUserPassAuthReqFrom(c.conn)
		if err != nil {
			return fmt.Errorf("NewUserPassAuthReqFrom:%w", err)
		}

		if req.Ver != SocksVersion {
			return ErrAuthUserPassVer
		}

		var status byte = AuthStatusFailure
		if string(req.UserName) == c.UserName && string(req.Password) == c.Password {
			status = AuthStatusSuccess
		}

		_, err = c.conn.Write(NewUserPassAuthReply(status).ToBytes())
		if err != nil {
			return fmt.Errorf("reply:%w", err)
		}

		if status != AuthStatusSuccess {
			return ErrAuthFailed
		}
		return nil
	default:
		return ErrMethod
	}
}
