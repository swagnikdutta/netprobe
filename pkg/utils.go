package pkg

import "fmt"

func PrintByteStream(topic string, stream []byte) {
	fmt.Printf("--------------- %s(hex) --------------\n", topic)
	for i := 0; i < len(stream); i++ {
		fmt.Printf("%02x ", stream[i])
	}
	fmt.Printf("\n\n")
}
