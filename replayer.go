package mudybluez

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/gopacket/pcapgo"
	"github.com/moznion/mudy-bluez/internal/packet"
)

const tcpProtocolNumber uint8 = 6

func replay(pcapNGPath string, tls bool) error {
	pcapFile, err := os.OpenFile(pcapNGPath, os.O_RDONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open a pcap file: %w", err)
	}

	pcapReader, err := pcapgo.NewNgReader(pcapFile, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return fmt.Errorf("failed to read a pcap file: %w", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	scheme := "http"
	if tls {
		scheme = "https"
	}

	sequenceNumberSet := map[uint32]bool{}

	ipv4PacketParser := &packet.IPv4Parser{}
	tcpPacketParser := &packet.TCPParser{}

	for {
		data, _, err := pcapReader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read packet: %w", err)
		}

		// XXX: this skips parsing the Ethernet frame

		ipPacket, err := ipv4PacketParser.Parse(data[4:])
		if err != nil {
			return fmt.Errorf("failed to parse IPv4 packet: %w", err)
		}
		if ipPacket.Protocol != tcpProtocolNumber {
			log.Printf("not a TCP packet; continue to the next packet")
			continue
		}

		tcpPacket, err := tcpPacketParser.Parse(ipPacket.Payload)
		if err != nil {
			return fmt.Errorf("failed to read a TCP packet: %w", err)
		}

		// dedup the same packet
		if sequenceNumberSet[tcpPacket.SeqNumber] {
			continue
		}

		httpReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(tcpPacket.Payload)))
		if err != nil {
			//log.Printf("failed to read a HTTP request (it might be not a HTTP protocol): %s", err)
			continue
		}

		endpoint := fmt.Sprintf("%s://%s%s", scheme, httpReq.Host, httpReq.RequestURI)
		u, err := url.Parse(endpoint)
		if err != nil {
			return fmt.Errorf("failed to parse request URL: %w", err)
		}
		httpReq.RequestURI = ""
		httpReq.URL = u

		resp, err := client.Do(httpReq)
		if err != nil {
			return fmt.Errorf("failed to send a HTTP request: %w", err)
		}

		sequenceNumberSet[tcpPacket.SeqNumber] = true
		log.Printf("sent %s %s: %d", httpReq.Method, endpoint, resp.StatusCode)
	}
}
