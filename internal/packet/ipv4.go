package packet

import (
	"encoding/binary"
	"fmt"
)

// from RFC 791
//
//     0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Version|  IHL  |Type of Service|          Total Length         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Identification        |Flags|      Fragment Offset    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Time to Live |    Protocol   |         Header Checksum       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Source Address                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Destination Address                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Options                    |    Padding    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IPv4 struct {
	Version        uint8
	IHL            uint8
	DSCP           uint8
	ECN            uint8
	TotalLength    uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SrcIPAddr      uint32
	DstIPAddr      uint32
	Options        []byte
	Payload        []byte
}

type IPv4Parser struct {
}

const minimumIPv4HeaderLen = 20

func (p *IPv4Parser) Parse(bs []byte) (*IPv4, error) {
	if len(bs) < minimumIPv4HeaderLen {
		return nil, fmt.Errorf("insufficient IPv4 packet data length: %d", len(bs))
	}

	ihl := bs[0] & 0x0f
	optionLen := 0
	if ihl > 5 {
		optionLen = int(ihl-5) * 4
	}
	totalLen := binary.BigEndian.Uint16(bs[2:4])
	return &IPv4{
		Version:        bs[0] >> 4,
		IHL:            bs[0] & 0b00001111,
		DSCP:           bs[1] >> 2,
		ECN:            bs[1] & 0b00000011,
		TotalLength:    totalLen,
		Identification: binary.BigEndian.Uint16(bs[4:6]),
		Flags:          bs[6] >> 5,
		FragmentOffset: binary.BigEndian.Uint16(bs[6:8]) & 0x1fff,
		TTL:            bs[8],
		Protocol:       bs[9],
		HeaderChecksum: binary.BigEndian.Uint16(bs[10:12]),
		SrcIPAddr:      binary.BigEndian.Uint32(bs[12:16]),
		DstIPAddr:      binary.BigEndian.Uint32(bs[16:20]),
		Options:        bs[20 : 20+optionLen],
		Payload:        bs[20+optionLen : totalLen],
	}, nil
}
