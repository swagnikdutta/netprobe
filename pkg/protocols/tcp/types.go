package tcp

import "net"

type Packet struct {
	Header  *Header
	Payload []byte
}

type Header struct {
	SourcePort      uint16
	DestinationPort uint16

	// Every octet of data(payload) sent over a TCP connection has a sequence number.
	// This field contain the sequence number of the first data octet in the segment (except when the SYN flag is set)
	// If SYN is set, the sequence number is the initial sequence number (ISN) and the first data octet is ISN+1
	SequenceNumber uint32

	// If the ACK control bit is set, this field contains the value of the next sequence number the sender of
	// the segment is expecting to receive. Once a connection is established, this is always sent.
	AcknowledgmentNumber uint32

	// Number of 32-bit words in the TCP header(including options). This indicates where the data begins.
	DataOffset uint8

	// A set of control bits reserved for future use. Must be 0 in generated segments.
	Reserved uint8

	// The correctly assigned control bits are CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
	Flags uint8

	// This field gives the number of data octets, beginning with the one indicated in the acknowledgement field that
	// the sender of this segment is willing to accept.
	// The window field is used for flow control, a mechanism used to ensure that a sender does not overwhelm a receiver
	// with data that it cannot process or store. It specifies the size of the receiver's window, i.e, the amount of
	// data, in bytes, that the receiver is currently willing to accept from the sender.
	// Throughout the duration of the connection, the receiver may adjust the window size dynamically based on its
	// buffer availability and processing capability.
	Window uint16

	// In addition to the usual way of computing checksums (using the internet checksum algorithm),
	// TCP checksum also covers a pseudo-header(96 bits for IPv4), prefixed to the TCP header. Including the
	// pseudo-header in the checksum gives the TCP connection protection against misrouted segments.
	Checksum uint16

	// Urgent pointer is used to indicate the end of the urgent data in the TCP segment. It's a positive
	// offset from SequenceNumber of the segment that points to the sequence number of the octet following
	// the urgent data. It is relevant only when the URG flag is set in the header
	UrgentPointer uint16

	// It is present only when DataOffset is greater than 5 (because TCP header takes 5 words).
	// Options occupy space at the end of the TCP header and are multiple of 8 bits in length. All options are included
	// in the checksum. An option may begin on any octet boundary. Note that, the list of options may be shorter than
	// what the data-offset field implies since data-offset is measured in 32-bit word lengths. In that case,
	// the content of the header beyond the end of `End of Option List` option must be padded with zeros.
	//
	// Option can have two formats
	// - a single octet (option-kind)
	// - a triplet of octets (option-kind, option-length, option-data)
	//
	//	option-length counts
	//	- two octets of option-kind and option-length,
	//	- as well as option data octet(s)
	//
	// A given TCP implementation must support the mandatory options:
	//   - End of Option List Option (EOLO): This is used to mark the end of all options (not every option) and need only be
	//     used if the end of options does not coincide with the end of TCP header(as per data offset field (32-bit words))
	//     - Kind: 1 byte, value = 0
	//
	//   - No-Operation (NOP): This option code can be used between options, for example, to align the beginning of a
	//     subsequent option on a word boundary. Although, there is no guarantee that senders will use this option, so
	//     receivers MUST be prepared to process options even if they do not begin on a word boundary.
	//     - Kind: 1 byte, value = 1
	//
	//   - Maximum Segment Size (MSS): The MSS option allows a TCP sender to inform the receiver of the maximum size of
	//     the TCP segment that it can receive without fragmentation. This helps optimize TCP performance by preventing
	//     excessive fragmentation and reassembly of TCP segments.
	//     This field may be sent in the initial connection request (i.e., in segments with the SYN control bit set)
	//     and MUST NOT be sent in other segments. If this segment is not used, any segment size is allowed.
	//     - Kind: 1 byte, value = 2
	//     - Length: 1 byte, value = 4
	//     - Data(MSS): 2 bytes, value = mss
	//
	//     MSS measures the non-header portion of the packet which is the payload. MSS defines the largest segment size
	//     the sender of the TCP packet can receive. It defines segment as only the length of the payload and not any
	//     attached headers. (Source: https://www.cloudflare.com/en-gb/learning/network-layer/what-is-mss/)
	//     MTU - (TCP header + IP header) = MSS
	//     1500 - (20 + 20) = 1460
	//
	//     One of the key differences between MTU and MSS is that if a packet exceeds a device's MTU, it is broken up into
	//     smaller pieces, or "fragmented." In contrast, if a packet exceeds the MSS, it is dropped and not delivered.
	//
	// All options except End of Option List Option (EOLO) and No-Operation (NOP) MUST have length fields, including
	// all future options.
	Options []Option
}

type Option struct {
	kind   byte
	length byte
	value  []byte
}

type PseudoHeader struct {
	// IPv4 source address in network byte order
	SourceAddress net.IP
	// IPv4 destination address in network byte order.
	DestinationAddress net.IP
	// bits set to zero
	zero uint8
	// protocol number from the IP header
	PTCL uint8
	// TCP header length plus data length in octets, and it does not count the 12 octets of the pseudo header
	TCPLength uint16
}
