package internal

import (
	"encoding/binary"
	"fmt"
)

type EtherType uint16

type EthernetFrame struct {
	DstMAC    []byte
	SrcMAC    []byte
	EtherType EtherType
	Payload   []byte
}

type EthernetFrameParser struct {
}

func (p *EthernetFrameParser) Parse(bs []byte) (*EthernetFrame, error) {
	if len(bs) < 18 {
		return nil, fmt.Errorf("insufficient data len: %d", len(bs))
	}
	return &EthernetFrame{
		DstMAC:    bs[0:6],
		SrcMAC:    bs[6:12],
		EtherType: EtherType(binary.BigEndian.Uint16(bs[12:14])),
		Payload:   bs[14:],
		// CRC
	}, nil
}
