package ping

func calculateChecksum(data []byte) uint16 {
	sum := uint32(0)

	// creating 16 bit words
	for i := 0; i < len(data)-1; i += 2 {
		word := uint32(data[i])<<8 | uint32(data[i+1])
		sum += word
	}
	if len(data)%2 == 1 { // validate this, might require padding
		sum += uint32(data[len(data)-1])
	}

	// adding carry bits with lower 16 bits
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// taking one's compliment
	checksum := ^sum
	return uint16(checksum)
}

// func (pinger *Pinger) printSerializedData(b []byte, name string) {
// 	fmt.Printf("%s bytes (hex)\n", name)
// 	for i := 0; i < len(b); i++ {
// 		fmt.Printf("%02x ", b[i])
// 	}
// 	fmt.Printf("\n\n")
// }
