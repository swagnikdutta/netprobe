package native_dns

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/swagnikdutta/netprobe/pkg"
)

var (
	typeA     uint16 = 1
	classINET uint16 = 1
)

type RRType uint16
type RRClass uint16

// Message is the format using which all communications in
// domain protocol are carried out. It is divided into five
// sections as shown below.
type Message struct {
	// Header is a 12 byte field
	Header *Header

	Question   *Question
	Answer     *Answer
	Authority  *Authority
	Additional *Additional
}

// Serialize serializes the structured resolver message into a stream of
// bytes that can be sent over the network.
//
// Serialization of a DNS packet is non-trivial. It has to be done
// according to DNS protocol standards.
//  1. use network byte order (big-endian)
//  2. ensure domain names in the QNAME field are encoded as per resolver
//     compression rules where domain names are represented as a sequence of
//     labels and pointers.
func (m *Message) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	headerSerialized, _ := m.Header.Serialize()
	questionSerialized, _ := m.Question.Serialize()

	pkg.PrintByteStream("message header section", headerSerialized)
	pkg.PrintByteStream("message question section", questionSerialized)
	buf.Write(headerSerialized)
	buf.Write(questionSerialized)

	return buf.Bytes(), nil
}

// Header section includes fields that specify which of the remaining
// sections of the Message format are present.
type Header struct {
	// ID is a 16 bit identifier assigned by the program that
	// generates any kind of query. The identifier is copied
	// to the corresponding reply and can be used by the requester
	// to match up replies to outstanding queries.
	ID uint16

	// QR is a 1 bit field that specifies if the message is a
	// query (0), or a response (1).
	QR uint8

	// Opcode is a 4 bit field that specifies the kind of query
	// in this message. The value (0 for standard query, 1 for
	// inverse query, etc.) is set by the originator of a query
	// and copied into the response.
	Opcode uint8

	// AA is authoritative answer. It's a 1-bit field that is valid in
	// responses, and specifies that the responding name server is
	// an authority for the domain name in Question section
	AA uint8

	// TC stands for truncation. It's a 1-bit field that specifies if
	// the message was truncated due to its length being greater than
	// that permitted on the transmission channel
	TC uint8

	// RD stands for Recursion Desired. It's a 1-bit field which might be
	// set in a query and is copied into the response. If RD is set, it
	// directs the name server to pursue the query recursively.
	RD uint8

	// RA stands for Recursion Available. It's a 1-bit field which is set
	// or cleared in the response and denotes whether recursive query support
	// is available in the name server.
	RA uint8

	// Z is a 3-bit field reserved for future use. Must be zero in all queries and responses.
	Z uint8

	// RCODE is response code. It's a 4 bit field set as a part of
	// responses. The values are,
	// 0	No error condition
	// 1	Format error
	// 2	Server failure
	// 3	Name Error
	// 4	Not Implemented
	// 5	Refused
	// 6	Reserved for future use
	RCODE uint8

	// QDCOUNT is a 16-bit integer that specifies number of entries
	// in the question section.
	// An entry refers to a resolver query or question. A resolver client can
	// include one or more entries in the question section to request
	// information about multiple domain names or resource records
	// in a single DNS query message.
	QDCOUNT uint16

	// ANCOUNT is a 16-bit integer that refers to the number of
	// Resource Records in answer section
	ANCOUNT uint16

	// NSCOUNT is a 16-bit integer that specifies the number of
	// name server resource records in the authority records section
	NSCOUNT uint16

	// ARCOUNT is a 16-bit integer that specifies the number of
	// Resource Records in the additional records section
	ARCOUNT uint16
}

func (h *Header) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, h.ID); err != nil {
		return nil, err
	}

	headerFlags := uint16(0)
	flagOffset := map[uint]uint16{
		15: uint16(h.QR),
		11: uint16(h.Opcode),
		10: uint16(h.AA),
		9:  uint16(h.TC),
		8:  uint16(h.RD),
		7:  uint16(h.RA),
		6:  uint16(h.Z),
		3:  uint16(h.RCODE),
	}

	for offset, flagValue := range flagOffset {
		headerFlags |= flagValue << offset
	}

	if err := binary.Write(buf, binary.BigEndian, headerFlags); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.QDCOUNT); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.ANCOUNT); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.NSCOUNT); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.ARCOUNT); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Question is the question for the name server. It contains
// fields(query type, query class and query domain name) that
// describe the question
type Question struct {
	// QName is a domain name represented as a sequence of labels,
	// where each label consists of a length octet followed by that
	// number of octets. The domain name terminates with the zero
	// length octet for the null label of the root.
	QName string

	// QType is a two octet code which specifies the type of the query
	//
	// type | value | meaning
	// A    | 1     | a host address
	// NS   | 2     | an authoritative name server
	QType RRType

	// QClass is a two octet code that specifies the class of the query.
	//
	// type | value | meaning
	// IN   | 1     | the Internet
	QClass RRClass
}

func (q *Question) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	domains := strings.Split(q.QName, ".")

	for _, subdomain := range domains {
		octetLength := len(subdomain)
		buf.WriteByte(byte(octetLength))

		for _, c := range subdomain {
			// here c is of type int32
			// convert into byte and append to buffer
			buf.WriteByte(byte(c))
		}
	}

	// domain name terminates with zero length octet
	// a byte is an alias for int8
	buf.WriteByte(0)

	// append queryType and queryClass
	binary.Write(buf, binary.BigEndian, uint16(1))
	binary.Write(buf, binary.BigEndian, uint16(1))
	serialized := buf.Bytes()

	return serialized, nil
}

type Answer struct {
	Records []ResourceRecord
}

type Authority struct {
	Records []ResourceRecord
}

type Additional struct {
	Records []ResourceRecord
}

type ResourceRecord struct {
	// an owner name, i.e., the name of the node to which this
	// resource record pertains.
	Name string

	// two octets containing one of the RR TYPE codes.
	Type RRType

	// two octets containing one of the RR CLASS codes.
	Class RRClass

	// TTL is a 32-bit signed integer that specifies the time
	// interval that the resource record may be cached before
	// the source of the information should again be consulted.
	TTL uint16

	// an unsigned 16-bit integer that specifies the length in octets
	// of the RDATA field.
	RDLENGTH uint16

	// a variable length string of octets that describes the
	// resource. The format of this information varies according
	// to the TYPE and CLASS of the resource record.
	RDATA []byte
}

func NewDNSMessage(host string) *Message {
	message := &Message{
		Header: &Header{
			ID:      1, // use a better identifier
			QR:      0, // 0 for query
			Opcode:  0, // 0 for standard query
			RD:      1,
			QDCOUNT: 1, // One question follows
		},
		Question: &Question{
			QName:  host,
			QType:  RRType(typeA),
			QClass: RRClass(classINET),
		},
	}

	return message
}
