package packet

import (
	"encoding/binary"
	"fmt"
)

// from RFC 793
//
//     0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          Source Port          |       Destination Port        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                        Sequence Number                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Acknowledgment Number                      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Data |           |U|A|P|R|S|F|                               |
//   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//   |       |           |G|K|H|T|N|N|                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |           Checksum            |         Urgent Pointer        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Options                    |    Padding    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                             data                              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type TCP struct {
	SrcPort       uint16
	DstPort       uint16
	SeqNumber     uint32
	AckNumber     uint32
	Offset        uint8
	URG           bool
	ACK           bool
	PSH           bool
	RST           bool
	SYN           bool
	FIN           bool
	WindowSize    uint16
	Checksum      uint16
	UrgentPointer uint16
	Option        []byte
	Payload       []byte
}

type TCPParser struct {
}

const minimumTCPHeaderLen = 20

func (p *TCPParser) Parse(bs []byte) (*TCP, error) {
	l := len(bs)
	if l < minimumTCPHeaderLen {
		return nil, fmt.Errorf("insufficient TCP packet data length, the minimum is %d: %d", minimumTCPHeaderLen, l)
	}

	offset := bs[12] & 0b11110000
	actualHeaderLen := offset / 4
	if l < int(actualHeaderLen) {
		return nil, fmt.Errorf("insufficient TCP packet data length, the expected is %d: %d", actualHeaderLen, l)
	}

	var option []byte
	payloadBeginIdx := minimumTCPHeaderLen
	if actualHeaderLen > minimumTCPHeaderLen {
		option = bs[minimumTCPHeaderLen : actualHeaderLen-1]
		payloadBeginIdx = int(actualHeaderLen)
	}

	return &TCP{
		SrcPort:       binary.BigEndian.Uint16(bs[0:2]),
		DstPort:       binary.BigEndian.Uint16(bs[2:4]),
		SeqNumber:     binary.BigEndian.Uint32(bs[4:8]),
		AckNumber:     binary.BigEndian.Uint32(bs[8:12]),
		Offset:        offset,
		URG:           (bs[13] & 0b00100000) == 0b00100000,
		ACK:           (bs[13] & 0b00010000) == 0b00010000,
		PSH:           (bs[13] & 0b00001000) == 0b00001000,
		RST:           (bs[13] & 0b00000100) == 0b00000100,
		SYN:           (bs[13] & 0b00000010) == 0b00000010,
		FIN:           (bs[13] & 0b00000001) == 0b00000001,
		WindowSize:    binary.BigEndian.Uint16(bs[14:16]),
		Checksum:      binary.BigEndian.Uint16(bs[16:18]),
		UrgentPointer: binary.BigEndian.Uint16(bs[18:20]),
		Option:        option,
		Payload:       bs[payloadBeginIdx:],
	}, nil
}
