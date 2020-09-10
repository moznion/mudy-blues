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

	sequenceNumberToActualStatusCode := map[uint32]int{}
	sequenceNumberToRequest := map[uint32]*http.Request{}

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
		if sequenceNumberToRequest[tcpPacket.AckNumber] != nil {
			continue
		}

		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(tcpPacket.Payload)))
		if err != nil {
			resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(tcpPacket.Payload)), sequenceNumberToRequest[tcpPacket.SeqNumber])
			if err != nil {
				// if it reaches here, the payload isn't HTTP
				continue
			}
			if resp.StatusCode != sequenceNumberToActualStatusCode[tcpPacket.SeqNumber] {
				log.Printf(
					"[ERROR] unexpected response status code; expected = %d, actual = %d, req = %s %s",
					sequenceNumberToActualStatusCode[tcpPacket.SeqNumber],
					resp.StatusCode,
					resp.Request.Method,
					resp.Request.URL,
				)
				continue
			}
			log.Printf(
				"[INFO] passed; expected = %d, actual = %d, req = %s %s",
				sequenceNumberToActualStatusCode[tcpPacket.SeqNumber],
				resp.StatusCode,
				resp.Request.Method,
				resp.Request.URL,
			)
			continue
		}

		endpoint := fmt.Sprintf("%s://%s%s", scheme, req.Host, req.RequestURI)
		u, err := url.Parse(endpoint)
		if err != nil {
			return fmt.Errorf("failed to parse request URL: %w", err)
		}
		req.RequestURI = ""
		req.URL = u

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send a HTTP request: %w", err)
		}

		sequenceNumberToActualStatusCode[tcpPacket.AckNumber] = resp.StatusCode
		sequenceNumberToRequest[tcpPacket.AckNumber] = req
		log.Printf("[INFO] sent %s %s: %d", req.Method, endpoint, resp.StatusCode)
	}
}
