package native_dns

import (
	"math/rand"
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
