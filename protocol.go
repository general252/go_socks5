package go_socks5

import (
	"fmt"
	"io"
	"net"
	"strconv"
)

type MethodSelectReq struct {
	Ver      byte
	NMethods byte
	Methods  []byte
}

func NewMethodSelectReq(methods []byte) *MethodSelectReq {
	return &MethodSelectReq{
		Ver:      SocksVersion,
		NMethods: byte(len(methods)),
		Methods:  methods,
	}
}

func NewMethodSelectReqFrom(r io.Reader) (*MethodSelectReq, error) {
	b := make([]byte, 2)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}

	nMethod := int(b[1])
	methods := make([]byte, nMethod)
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, err
	}

	return &MethodSelectReq{
		Ver:      0x05,
		NMethods: byte(nMethod),
		Methods:  methods,
	}, nil
}

func (p *MethodSelectReq) ToBytes() []byte {
	ret := []byte{p.Ver, p.NMethods}
	ret = append(ret, p.Methods...)
	return ret
}

type MethodSelectReply struct {
	Ver    byte
	Method MethodType
}

func NewMethodSelectReply(method MethodType) *MethodSelectReply {
	return &MethodSelectReply{
		Ver:    SocksVersion,
		Method: method,
	}
}

func NewMethodSelectReplyFrom(r io.Reader) (*MethodSelectReply, error) {
	b := make([]byte, 2)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}

	return &MethodSelectReply{
		Ver:    b[0],
		Method: MethodType(b[1]),
	}, nil
}

func (p *MethodSelectReply) ToBytes() []byte {
	return []byte{p.Ver, byte(p.Method)}
}

type UserPassAuthReq struct {
	Ver      byte
	ULen     byte
	UserName []byte
	PLen     byte
	Password []byte
}

func NewUserPassAuthReq(username []byte, password []byte) *UserPassAuthReq {
	return &UserPassAuthReq{
		Ver:      SocksVersion,
		ULen:     byte(len(username)),
		UserName: username,
		PLen:     byte(len(password)),
		Password: password,
	}
}

func NewUserPassAuthReqFrom(r io.Reader) (*UserPassAuthReq, error) {
	b := make([]byte, 1)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}

	ver := b[0]

	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}

	uLen := int(b[0])
	userName := make([]byte, uLen)
	if _, err := io.ReadFull(r, userName); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}

	pLen := int(b[0])
	password := make([]byte, pLen)
	if _, err := io.ReadFull(r, password); err != nil {
		return nil, err
	}

	return &UserPassAuthReq{
		Ver:      ver,
		ULen:     byte(uLen),
		UserName: userName,
		PLen:     byte(pLen),
		Password: password,
	}, nil
}

func (p *UserPassAuthReq) ToBytes() []byte {
	ret := []byte{p.Ver, p.ULen}
	ret = append(ret, p.UserName...)
	ret = append(ret, p.PLen)
	ret = append(ret, p.Password...)
	return ret
}

type UserPassAuthReply struct {
	Ver    byte
	Status byte
}

func (p *UserPassAuthReply) ToBytes() []byte {
	return []byte{p.Ver, p.Status}
}

func NewUserPassAuthReply(status byte) *UserPassAuthReply {
	return &UserPassAuthReply{
		Ver:    SocksVersion,
		Status: status,
	}
}

func NewUserPassAuthReplyFrom(r io.Reader) (*UserPassAuthReply, error) {
	b := make([]byte, 2)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return &UserPassAuthReply{
		Ver:    b[0],
		Status: b[1],
	}, nil
}

type Request struct {
	Ver     byte
	Cmd     byte
	Rsv     byte //0x00
	ATyp    byte
	DstAddr []byte
	DstPort []byte //2 bytes
}

func NewRequestFrom(r io.Reader) (*Request, error) {
	b := []byte{0, 0, 0}
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}

	addrByte, err := NewAddrByteFrom(r)
	if err != nil {
		return nil, err
	}

	aType, addr, port := addrByte.Split()

	return &Request{
		Ver:     b[0],
		Cmd:     b[1],
		Rsv:     b[2],
		ATyp:    aType,
		DstAddr: addr,
		DstPort: port,
	}, nil
}

func NewRequest(cmd byte, addrByte AddrByte) *Request {
	aType, addr, port := addrByte.Split()
	return &Request{
		Ver:     SocksVersion,
		Cmd:     cmd,
		Rsv:     0,
		ATyp:    aType,
		DstAddr: addr,
		DstPort: port,
	}
}

func (p *Request) Address() string {
	var bAddr []byte
	bAddr = append(bAddr, p.ATyp)
	bAddr = append(bAddr, p.DstAddr...)
	bAddr = append(bAddr, p.DstPort...)
	return AddrByte(bAddr).String()
}

func (p *Request) ToBytes() []byte {
	ret := []byte{p.Ver, p.Cmd, p.Rsv, p.ATyp}
	ret = append(ret, p.DstAddr...)
	ret = append(ret, p.DstPort...)
	return ret
}

type Reply struct {
	Ver     byte
	Rep     byte
	Rsv     byte
	ATyp    byte
	BndAddr []byte
	BndPort []byte //2 bytes
}

func (p *Reply) Address() string {
	var bAddr []byte
	bAddr = append(bAddr, p.ATyp)
	bAddr = append(bAddr, p.BndAddr...)
	bAddr = append(bAddr, p.BndPort...)
	return AddrByte(bAddr).String()
}

func (p *Reply) ToBytes() []byte {
	ret := []byte{p.Ver, p.Rep, p.Rsv, p.ATyp}
	ret = append(ret, p.BndAddr...)
	ret = append(ret, p.BndPort...)
	return ret
}

func NewReply(rep byte, addrByte AddrByte) *Reply {
	aType, addr, port := addrByte.Split()
	return &Reply{
		Ver:     SocksVersion,
		Rep:     rep,
		Rsv:     0,
		ATyp:    aType,
		BndAddr: addr,
		BndPort: port,
	}
}

func NewReplyFrom(r io.Reader) (*Reply, error) {
	b := []byte{0, 0, 0}
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}

	addrByte, err := NewAddrByteFrom(r)
	if err != nil {
		return nil, err
	}

	aType, addr, port := addrByte.Split()

	return &Reply{
		Ver:     b[0],
		Rep:     b[1],
		Rsv:     b[2],
		ATyp:    aType,
		BndAddr: addr,
		BndPort: port,
	}, nil
}

type UDPDatagram struct {
	Rsv     []byte //0x00,0x00
	Frag    byte
	AType   byte
	DstAddr []byte
	DstPort []byte
	Data    []byte
}

func (p *UDPDatagram) ToBytes() []byte {
	var b []byte
	b = append(b, p.Rsv...)
	b = append(b, p.Frag)
	b = append(b, p.AType)
	b = append(b, p.DstAddr...)
	b = append(b, p.DstPort...)
	b = append(b, p.Data...)
	return b
}

func (p *UDPDatagram) Address() string {
	var bAddr []byte
	bAddr = append(bAddr, p.AType)
	bAddr = append(bAddr, p.DstAddr...)
	bAddr = append(bAddr, p.DstPort...)
	return AddrByte(bAddr).String()
}

func NewUDPDatagram(addrByte AddrByte, data []byte) *UDPDatagram {
	aType, addr, port := addrByte.Split()
	return &UDPDatagram{
		Rsv:     []byte{0, 0},
		Frag:    0,
		AType:   aType,
		DstAddr: addr,
		DstPort: port,
		Data:    data,
	}
}

func NewUDPDatagramFromBytes(b []byte) (*UDPDatagram, error) {
	if len(b) < 4 {
		return nil, ErrBadRequest
	}

	bAddr, err := NewAddrByteFromByte(b[3:])
	if err != nil {
		return nil, err
	}

	data := b[3+len(bAddr):]
	return NewUDPDatagram(bAddr, data), nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const MaxAddrLen = 1 + 1 + 255 + 2
const PortLen = 2

type AddrByte []byte

func (a AddrByte) String() string {
	var host, port string

	switch a[0] { // address type
	case ATypDomain:
		host = string(a[2 : 2+int(a[1])])
		port = strconv.Itoa((int(a[2+int(a[1])]) << 8) | int(a[2+int(a[1])+1]))
	case ATypIPv4:
		host = net.IP(a[1 : 1+net.IPv4len]).String()
		port = strconv.Itoa((int(a[1+net.IPv4len]) << 8) | int(a[1+net.IPv4len+1]))
	case ATypIPv6:
		host = net.IP(a[1 : 1+net.IPv6len]).String()
		port = strconv.Itoa((int(a[1+net.IPv6len]) << 8) | int(a[1+net.IPv6len+1]))
	}

	return net.JoinHostPort(host, port)
}

func (a AddrByte) Split() (aType byte, addr []byte, port []byte) {
	aType = ATypIPv4
	addr = []byte{0, 0, 0, 0}
	port = []byte{0, 0}

	if a != nil {
		aType = a[0]
		addr = a[1 : len(a)-2]
		port = a[len(a)-2:]
	}
	return
}

func NewAddrByteFromString(s string) (AddrByte, error) {
	var addr []byte

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("addr:%s SplitHostPort %v", s, err)
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = make([]byte, 1+net.IPv4len+2)
			addr[0] = ATypIPv4
			copy(addr[1:], ip4)
		} else {
			addr = make([]byte, 1+net.IPv6len+2)
			addr[0] = ATypIPv6
			copy(addr[1:], ip)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("host:%s too long", host)
		}

		addr = make([]byte, 1+1+len(host)+2)
		addr[0] = ATypDomain
		addr[1] = byte(len(host))
		copy(addr[2:], host)
	}

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("port:%s ParseUint %v", port, err)
	}

	addr[len(addr)-2], addr[len(addr)-1] = byte(portNum>>8), byte(portNum)
	return addr, nil
}

func NewAddrByteFrom(r io.Reader) (AddrByte, error) {
	b := make([]byte, MaxAddrLen)

	_, err := io.ReadFull(r, b[:1])
	if err != nil {
		return nil, err
	}

	var startPos = 1
	var addrLen int
	switch b[0] {
	case ATypDomain:
		_, err := io.ReadFull(r, b[1:2])
		if err != nil {
			return nil, err
		}
		startPos++
		addrLen = int(b[1])
	case ATypIPv4:
		addrLen = net.IPv4len
	case ATypIPv6:
		addrLen = net.IPv6len
	default:
		return nil, ErrAddrType
	}

	endPos := startPos + addrLen + PortLen

	_, err = io.ReadFull(r, b[startPos:endPos])
	return b[:endPos], err
}

func NewAddrByteFromByte(b []byte) (AddrByte, error) {
	if len(b) < 1 {
		return nil, ErrBadRequest
	}
	var startPos = 1
	var addrLen int
	switch b[0] {
	case ATypDomain:
		if len(b) < 2 {
			return nil, ErrBadRequest
		}
		startPos++
		addrLen = int(b[1])
	case ATypIPv4:
		addrLen = net.IPv4len
	case ATypIPv6:
		addrLen = net.IPv6len
	default:
		return nil, ErrAddrType
	}

	endPos := startPos + addrLen + PortLen

	if len(b) < endPos {
		return nil, ErrBadRequest
	}
	return b[:endPos], nil
}
