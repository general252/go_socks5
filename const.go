package go_socks5

import (
	"errors"
	"fmt"
)

const (
	SocksVersion byte = 0x05
)

const (
	CmdConnect      byte = 0x01
	CmdBind         byte = 0x02
	CmdUdpAssociate byte = 0x03
)

type MethodType byte

const (
	MethodNoAuth       MethodType = 0x00
	MethodUserPass     MethodType = 0x02
	MethodNoAcceptable MethodType = 0xff
)

const (
	ATypIPv4   byte = 0x01
	ATypDomain byte = 0x03
	ATypIPv6   byte = 0x04
)

const (
	AuthStatusSuccess = 0x00
	AuthStatusFailure = 0x01
)

const (
	RepSuccess              = 0x00
	RepServerFailure        = 0x01
	RepRuleFailure          = 0x02
	RepNetworkUnreachable   = 0x03
	RepHostUnreachable      = 0x04
	RepConnectionRefused    = 0x05
	RepTTLExpired           = 0x06
	RepCmdNotSupported      = 0x07
	RepAddrTypeNotSupported = 0x08
)

var (
	ErrMethodNoAcceptable = errors.New("no acceptable method")
	ErrAuthFailed         = errors.New("user authentication failed")
	NoSupportedAuth       = errors.New("no supported auth")
	ErrAuthUserPassVer    = errors.New("auth user pass version")
	ErrCmdNotSupport      = errors.New("cmd not support")

	ErrAddrType     = fmt.Errorf("unrecognized address type")
	ErrSocksVersion = fmt.Errorf("not socks version 5")
	ErrMethod       = fmt.Errorf("unsupport method")
	ErrBadRequest   = fmt.Errorf("bad request")
	ErrUDPFrag      = fmt.Errorf("frag !=0 not supported")
)
