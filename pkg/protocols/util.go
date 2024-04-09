package protocols

import (
	"bytes"
	"encoding/binary"
	"net"
)

func CalculateChecksum(data []byte) uint16 {
	if len(data)%2 == 1 {
		data = append(data, 0x00)
	}

	sum := uint32(0)
	// creating 16 bit words
	for i := 0; i < len(data)-1; i += 2 {
		word := uint32(data[i])<<8 | uint32(data[i+1])
		sum += word
	}

	// adding carry bits with lower 16 bits
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// taking one's compliment
	checksum := ^sum
	return uint16(checksum)
}

func WriteBinary(buf *bytes.Buffer, values ...interface{}) error {
	for _, value := range values {
		if ip, ok := value.(net.IP); ok {
			octets := ip.To4()
			if err := WriteBinary(buf, octets[0], octets[1], octets[2], octets[3]); err != nil {
				return err
			}
			continue
		}

		if err := binary.Write(buf, binary.BigEndian, value); err != nil {
			return err
		}
	}
	return nil
}
