package dig

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"

	"github.com/swagnikdutta/netprobe/pkg/protocols"
)

var (
	typeA     uint16 = 1
	classINET uint16 = 1

	flagInfo = map[string]struct {
		offset uint8
		mask   uint16
	}{
		"QR":     {15, 0x8000},
		"Opcode": {11, 0x7800},
		"AA":     {10, 0x0400},
		"TC":     {9, 0x0200},
		"RD":     {8, 0x0100},
		"RA":     {7, 0x0080},
		"Z":      {6, 0x0070},
		"RCODE":  {3, 0x000f},
	}
)

type RRType uint16
type RRClass uint16

// Message is the format using which all communications in
// domain protocol are carried out. It is divided into five
// sections as shown below.
type Message struct {
	// Header section includes fields that specify which of the remaining sections
	// are present, and also specify whether the message is a query or a response,
	// a standard query or some other opcode, etc.
	Header *Header

	// Question section contains fields that describe a question to a name server
	Question *Question

	// Answer section contains RRs that answer the question
	Answer *Answer

	// Authority section contains RRs that point toward an authoritative name server
	Authority *Authority

	// Additional records section contains RRs which relate to the query,
	// but are not strictly answers for the question.
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
	buf.Write(headerSerialized)
	buf.Write(questionSerialized)

	return buf.Bytes(), nil
}

func (m *Message) Deserialize(stream []byte) {
	m.Header.Deserialize(stream)

	offset := uint16(12)
	if m.Header.QDCOUNT != 0 {
		m.Question.Deserialize(stream, &offset)
	}
	if m.Header.ANCOUNT != 0 {
		m.Answer.Deserialize(stream, &offset, m.Header.ANCOUNT)
	}
	if m.Header.NSCOUNT != 0 {
		m.Authority.Deserialize(stream, &offset, m.Header.NSCOUNT)
	}
	if m.Header.ARCOUNT != 0 {
		m.Additional.Deserialize(stream, &offset, m.Header.ARCOUNT)
	}
}

func (m *Message) hasAnswer() (*ResourceRecord, bool) {
	if m.Header.ANCOUNT == 0 {
		return nil, false
	}

	return m.Answer.Records[0], true
}

func (m *Message) hasGlueRecord() (*ResourceRecord, bool) {
	if m.Header.ARCOUNT == 0 {
		return nil, false
	}

	var glue *ResourceRecord
	for i := 0; i < int(m.Header.ARCOUNT); i++ {
		if m.Additional.Records[i].Type == 1 {
			glue = m.Additional.Records[i]
			return glue, true
		}
	}

	return nil, false
}

func (m *Message) hasNSRecord() (*ResourceRecord, bool) {
	if m.Header.NSCOUNT == 0 {
		return nil, false
	}

	var ns *ResourceRecord
	for i := 0; i < int(m.Header.NSCOUNT); i++ {
		// sometimes authority section can have SOA (type 6) records. This has
		// been the case for domains that doesn't exist eg: abcd.com
		if m.Authority.Records[i].Type == 2 {
			ns = m.Authority.Records[i]
			return ns, true
		}
	}

	return nil, false
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
	for flagName, info := range flagInfo {
		switch flagName {
		case "QR":
			headerFlags |= uint16(h.QR) << info.offset
		case "Opcode":
			headerFlags |= uint16(h.QR) << info.offset
		case "AA":
			headerFlags |= uint16(h.QR) << info.offset
		case "TC":
			headerFlags |= uint16(h.QR) << info.offset
		case "RD":
			headerFlags |= uint16(h.QR) << info.offset
		case "RA":
			headerFlags |= uint16(h.QR) << info.offset
		case "Z":
			headerFlags |= uint16(h.QR) << info.offset
		case "RCODE":
			headerFlags |= uint16(h.QR) << info.offset
		}
	}

	if err := protocols.WriteBinary(buf, headerFlags, h.QDCOUNT, h.ANCOUNT, h.NSCOUNT, h.ARCOUNT); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (h *Header) Deserialize(stream []byte) {
	h.ID = binary.BigEndian.Uint16(stream[:2])

	flags := binary.BigEndian.Uint16(stream[2:4])
	for flagName, info := range flagInfo {
		value := (flags & info.mask) >> info.offset
		switch flagName {
		case "QR":
			h.QR = uint8(value)
		case "Opcode":
			h.Opcode = uint8(value)
		case "AA":
			h.AA = uint8(value)
		case "TC":
			h.TC = uint8(value)
		case "RD":
			h.RD = uint8(value)
		case "RA":
			h.RA = uint8(value)
		case "Z":
			h.Z = uint8(value)
		case "RCODE":
			h.RCODE = uint8(value)
		}
	}

	h.QDCOUNT = binary.BigEndian.Uint16(stream[4:6])
	h.ANCOUNT = binary.BigEndian.Uint16(stream[6:8])
	h.NSCOUNT = binary.BigEndian.Uint16(stream[8:10])
	h.ARCOUNT = binary.BigEndian.Uint16(stream[10:12])
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
			// here c is a rune (alias for int32)
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

func (q *Question) Deserialize(stream []byte, offset *uint16) {
	q.QName = readVariableLengthField(stream, offset)

	q.QType = RRType(binary.BigEndian.Uint16(stream[*offset : *offset+2]))
	*offset += 2

	q.QClass = RRClass(binary.BigEndian.Uint16(stream[*offset : *offset+2]))
	*offset += 2
}

type Answer struct {
	Records []*ResourceRecord
}

func (a *Answer) Deserialize(stream []byte, offset *uint16, ancount uint16) {
	a.Records = make([]*ResourceRecord, ancount)

	for i := 0; i < int(ancount); i++ {
		a.Records[i] = new(ResourceRecord)
		a.Records[i].Deserialize(stream, offset)
	}
}

type Authority struct {
	Records []*ResourceRecord
}

func (a *Authority) Deserialize(stream []byte, offset *uint16, nscount uint16) {
	a.Records = make([]*ResourceRecord, nscount)

	for i := 0; i < int(nscount); i++ {
		a.Records[i] = new(ResourceRecord)
		a.Records[i].Deserialize(stream, offset)
	}
}

type Additional struct {
	Records []*ResourceRecord
}

func (a *Additional) Deserialize(stream []byte, offset *uint16, arcount uint16) {
	a.Records = make([]*ResourceRecord, arcount)

	for i := 0; i < int(arcount); i++ {
		a.Records[i] = new(ResourceRecord)
		a.Records[i].Deserialize(stream, offset)
	}
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
	// to the TYPE and CLASS of the resource record. For example,
	// if the TYPE is A and the CLASS is IN, the RDATA field
	// is a 4 octet ARPA Internet address.
	RDATA string
}

func (rr *ResourceRecord) Deserialize(stream []byte, offset *uint16) {
	rr.Name = readVariableLengthField(stream, offset)
	rr.Type = RRType(binary.BigEndian.Uint16(stream[*offset : *offset+2]))
	*offset += 2

	rr.Class = RRClass(binary.BigEndian.Uint16(stream[*offset : *offset+2]))
	*offset += 2

	rr.TTL = binary.BigEndian.Uint16(stream[*offset : *offset+4])
	*offset += 4

	rr.RDLENGTH = binary.BigEndian.Uint16(stream[*offset : *offset+2])
	*offset += 2

	if rr.Type == 1 || rr.Type == 28 {
		// 1 for A, 28 for AAAA
		rr.RDATA = net.IP(stream[*offset : *offset+rr.RDLENGTH]).String()
		*offset += rr.RDLENGTH
	} else if rr.Type == 2 || rr.Type == 5 {
		// 2 for NS, 5 for CNAME
		rr.RDATA = readVariableLengthField(stream, offset)
	}
}

func NewDNSMessage() *Message {
	message := &Message{
		Header:     &Header{},
		Question:   &Question{},
		Answer:     &Answer{},
		Authority:  &Authority{},
		Additional: &Additional{},
	}

	return message
}

func NewDNSQuery(host string, txnID uint16) *Message {
	query := NewDNSMessage()

	query.Header.ID = txnID
	query.Header.RD = 1
	query.Header.QDCOUNT = 1

	query.Question.QName = host
	query.Question.QType = RRType(typeA)
	query.Question.QClass = RRClass(classINET)

	return query
}
