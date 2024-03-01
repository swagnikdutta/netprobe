package tcp

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"net"

	"github.com/pkg/errors"
	"github.com/swagnikdutta/netprobe/pkg/protocols"
	"github.com/swagnikdutta/netprobe/pkg/protocols/ipv4"
)

var (
	isn      uint32 = 0
	protoTCP uint8  = 6
	flagSYN  uint8  = 2
	mss      uint16 = 1460
)

func init() {
	dest := net.IP{192, 0, 2, 1}
	// handshake should return a connection IMO
	handshake(dest)
}

func createHeader(
	srcPort uint16,
	destPort uint16,
	seqNo uint32,
	ackNo uint32,
	do uint8,
	rsvd uint8,
	flags uint8,
	win uint16,
	checksum uint16,
	urg uint16,
	opts []*Option,
) *Header {
	return &Header{
		SourcePort:           srcPort,
		DestinationPort:      destPort,
		SequenceNumber:       seqNo,
		AcknowledgmentNumber: ackNo,
		DataOffset:           do,
		Reserved:             rsvd,
		Flags:                flags,
		Window:               win,
		Checksum:             checksum,
		UrgentPointer:        urg,
		Options:              opts,
	}
}

func calculateDataOffset(opts []*Option) uint8 {
	wLenHeader := uint8(5)
	buf := new(bytes.Buffer)

	for _, o := range opts {
		_ = protocols.WriteBinary(buf, o.kind, o.length, o.value)
	}
	options := buf.Bytes()
	wLenOptions := uint8(math.Ceil(float64(len(options)) / 4.0))
	return wLenHeader + wLenOptions
}

func createPacket(
	src,
	dest net.IP,
	flags uint8,
	payload []byte,
) (*Packet, []byte, error) {

	var opts []*Option
	if flags == flagSYN {
		opts = append(opts, &Option{kind: 2, length: 4, value: mss})
	}

	dOffset := calculateDataOffset(opts)
	header := createHeader(1234, 8080, isn, 0, dOffset, 0, flags, 0, 0, 0, opts)
	headerSerialized, err := header.Serialize()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error serializing tcp header")
	}

	pseudo := &PseudoHeader{
		SourceAddress:      src,
		DestinationAddress: dest,
		zero:               0,
		PTCL:               protoTCP,
		TCPLength:          uint16(len(headerSerialized) + len(payload)),
	}
	pseudoSerialized, err := pseudo.Serialize()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error serializing pseudo header")
	}

	combined := append(pseudoSerialized, headerSerialized...)
	checksum := protocols.CalculateChecksum(combined)

	p := &Packet{
		Header:  header,
		Payload: payload,
	}
	p.Header.Checksum = checksum

	packetSerialized, err := p.Serialize()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error serializing tcp packet")
	}

	return p, packetSerialized, nil
}

func handshake(dest net.IP) {
	// As of now, we know the ip of the remote end of the network tunnel
	src := net.IP{192, 0, 2, 2}

	syn, synSerialized, err := createPacket(src, dest, flagSYN, nil)
	if err != nil {
		log.Fatal("error creating TCP SYN packet")
	}
	_ = syn

	ipHeader := ipv4.CreateHeader(4, 5, 0, uint16(20+len(synSerialized)), 1, 0, 0, 64, protoTCP, 0, src, dest)
	ipPacket, ipSerialized, err := ipv4.CreatePacket(ipHeader, synSerialized)
	if err != nil {
		log.Fatalf("error creating ip packet: %v", err)
	}
	_ = ipPacket

	addr := fmt.Sprintf("%s:%s", dest.String(), "8080")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	log.Println("writing syn packet on connection")
	_, err = conn.Write(ipSerialized)
	if err != nil {
		log.Fatalf("error writing syn packet on connection: %v", err)
	}

	reply := make([]byte, 2048)
	_, err = conn.Read(reply)
	if err != nil {
		log.Fatalf("error reading reply: %v", err)
	}
}
