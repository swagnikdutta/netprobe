package dig

import (
	"math/rand"
	"net"
	"strings"
	"time"
)

func isPointer(b uint8) bool {
	return b>>6 == 3
}

func readVariableLengthField(stream []byte, offset *uint16) string {
	var sb strings.Builder
	var res string

	for {
		currentByte := stream[*offset]

		if isPointer(currentByte) {
			nextByte := stream[*offset+1]
			combined := uint16(currentByte)<<8 | uint16(nextByte)
			ptrOffset := combined & 0x3fff
			label := readVariableLengthField(stream, &ptrOffset)
			sb.WriteString(label)
			*offset += 2

			entire := sb.String()
			return entire
		} else {
			// null byte
			if currentByte == 0 {
				res = sb.String()
				res = res[:len(res)-1]
				*offset++
				break
			}
			labelLength := currentByte
			start, end := *offset+1, *offset+uint16(labelLength)+1
			sb.Write(stream[start:end])
			sb.WriteByte(0x2e)
			*offset = end
		}
	}

	return res
}

func (r *Resolver) generateTxnID() uint16 {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	res := uint16(random.Intn(65536))

	if _, exists := r.Meta.TxnIDMap[res]; exists {
		return r.generateTxnID()
	}

	r.Meta.TxnIDMap[res] = nil
	return res
}

func getNameserverIP() net.IP {
	nameserverAddress := map[string]net.IP{
		"a": net.IP{198, 41, 0, 4},
		"b": net.IP{170, 247, 170, 2},
		"c": net.IP{192, 33, 4, 12},
		"d": net.IP{199, 7, 91, 13},
		"e": net.IP{192, 203, 230, 10},
		"f": net.IP{192, 5, 5, 241},
		"g": net.IP{192, 112, 36, 4},
		"h": net.IP{198, 97, 190, 53},
		"i": net.IP{192, 36, 148, 17},
		"j": net.IP{192, 58, 128, 30},
		"k": net.IP{193, 0, 14, 129},
		"l": net.IP{199, 7, 83, 42},
		"m": net.IP{202, 12, 27, 33},
	}
	// TODO: Would be great to have a fallback logic if the default nameserver does not respond
	defaultNameserver := "b"
	return nameserverAddress[defaultNameserver]
}
