package tcp

import (
	"log"
	"net"

	"github.com/pkg/errors"
	"github.com/swagnikdutta/netprobe/pkg"
	"github.com/swagnikdutta/netprobe/pkg/protocols"
)

var (
	InitialSequenceNumber uint32 = 0
	TCPProtocolNumber     uint8  = 6
)

func init() {
	doStuff()
}

func CreateSYNPacket() ([]byte, error) {
	p := &Packet{
		Header: &Header{
			SourcePort:      1234,
			DestinationPort: 8080,
			SequenceNumber:  InitialSequenceNumber,
			DataOffset:      5, // 5, if there are no options
			Flags:           2, // For SYN packet
			Window:          0,
		},
	}
	pseudo := &PseudoHeader{
		SourceAddress:      net.IP{192, 0, 2, 1},
		DestinationAddress: net.IP{192, 0, 2, 2},
		zero:               0,
		PTCL:               TCPProtocolNumber,
		TCPLength:          0,
	}

	pseudoSerialized, err := pseudo.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing pseudo header")
	}

	headerSerialized, err := p.Header.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing tcp header")
	}

	combined := append(pseudoSerialized, headerSerialized...)
	p.Header.Checksum = protocols.CalculateChecksum(combined)

	packetSerialized, err := p.Serialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing tcp packet")
	}

	return packetSerialized, nil
}

func doStuff() {
	// device, err := tun.CreateTUN("utun0", 1300)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// // device.Write()
	// fmt.Println(device)

	packet, err := CreateSYNPacket()
	if err != nil {
		log.Fatal("error creating TCP SYN packet")
	}
	pkg.PrintByteStream("tcp packet", packet)
}
