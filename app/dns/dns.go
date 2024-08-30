package dns

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// DNSMessage represents a complete DNS message.
type DNSMessage struct {
	Header          DNSHeader
	Questions       []DNSQuestion
	ResourceRecords []DNSResourceRecords
}

// Serialize serializes the DNSMessage into a byte slice.
func (dnsMessage DNSMessage) Serialize() []byte {
	buffer := []byte{}
	buffer = append(buffer, dnsMessage.Header.Serialize()...)
	for _, question := range dnsMessage.Questions {
		buffer = append(buffer, question.Serialize()...)
	}
	for _, rr := range dnsMessage.ResourceRecords {
		buffer = append(buffer, rr.Serialize()...)
	}
	return buffer
}

// CreateNewDnsMessage creates a new DNSMessage from the provided byte slice.
func CreateNewDnsMessage(buffer []byte) DNSMessage {
	query := parseHeader(buffer)
	questions := parseQuestions(buffer, query.QDCOUNT)
	answers := []DNSResourceRecords{}
	for _, question := range questions {
		answers = append(answers, DNSResourceRecords{
			Name:     question.Name,
			Type:     1,
			Class:    1,
			TTL:      0,
			RDLength: 4,
			RData:    []byte("\x08\x08\x08\x08"), // Placeholder RData
		})
	}
	var rCode uint8
	if query.OPCODE != 0 {
		rCode = 4
	} else {
		rCode = 0
	}
	headers := DNSHeader{
		ID:      query.ID,
		QR:      1,
		OPCODE:  query.OPCODE,
		AA:      0,
		TC:      0,
		RD:      query.RD,
		RA:      0,
		Z:       0,
		RCODE:   rCode,
		QDCOUNT: uint16(len(questions)),
		ANCOUNT: uint16(len(answers)),
		NSCOUNT: query.NSCOUNT,
		ARCOUNT: query.ARCOUNT,
	}
	return DNSMessage{
		Header:          headers,
		Questions:       questions,
		ResourceRecords: answers,
	}
}

// DNSHeader represents the header section of a DNS message.
type DNSHeader struct {
	ID      uint16 // Packet Identifier (ID)
	QR      uint8  // Query/Response Indicator (QR)
	OPCODE  uint8  // Operation Code (OPCODE)
	AA      uint8  // Authoritative Answer (AA)
	TC      uint8  // Truncation (TC)
	RD      uint8  // Recursion Desired (RD)
	RA      uint8  // Recursion Available (RA)
	Z       uint8  // Reserved (Z)
	RCODE   uint8  // Response Code (RCODE)
	QDCOUNT uint16 // Question Count (QDCOUNT)
	ANCOUNT uint16 // Answer Record Count (ANCOUNT)
	NSCOUNT uint16 // Authority Record Count (NSCOUNT)
	ARCOUNT uint16 // Additional Record Count (ARCOUNT)
}

// Serialize serializes the DNSHeader into a byte slice.
func (header DNSHeader) Serialize() []byte {
	buffer := make([]byte, 12)
	binary.BigEndian.PutUint16(buffer[0:2], header.ID)
	buffer[2] = (header.QR << 7) | (header.OPCODE << 3) | (header.AA << 2) | (header.TC << 1) | header.RD
	buffer[3] = (header.RA << 7) | (header.Z << 4) | header.RCODE
	binary.BigEndian.PutUint16(buffer[4:6], header.QDCOUNT)
	binary.BigEndian.PutUint16(buffer[6:8], header.ANCOUNT)
	binary.BigEndian.PutUint16(buffer[8:10], header.NSCOUNT)
	binary.BigEndian.PutUint16(buffer[10:12], header.ARCOUNT)
	return buffer
}

// DNSQuestion represents a DNS question.
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// Serialize serializes the DNSQuestion into a byte slice.
func (question DNSQuestion) Serialize() []byte {
	buffer := []byte{}
	labels := strings.Split(question.Name, ".")
	for _, label := range labels {
		buffer = append(buffer, byte(len(label)))
		buffer = append(buffer, []byte(label)...)
	}
	buffer = append(buffer, '\x00')
	buffer = append(buffer, byte(question.Type>>8), byte(question.Type))
	buffer = append(buffer, byte(question.Class>>8), byte(question.Class))
	return buffer
}

// DNSResourceRecords represents a DNS resource record.
type DNSResourceRecords struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

// Serialize serializes the DNSResourceRecords into a byte slice.
func (answer DNSResourceRecords) Serialize() []byte {
	buffer := []byte{}
	labels := strings.Split(answer.Name, ".")
	for _, label := range labels {
		buffer = append(buffer, byte(len(label)))
		buffer = append(buffer, []byte(label)...)
	}
	buffer = append(buffer, '\x00')
	buffer = append(buffer, byte(answer.Type>>8), byte(answer.Type))
	buffer = append(buffer, byte(answer.Class>>8), byte(answer.Class))
	buffer = append(buffer, byte(answer.TTL>>24), byte(answer.TTL>>16), byte(answer.TTL>>8), byte(answer.TTL))
	buffer = append(buffer, byte(answer.RDLength>>8), byte(answer.RDLength))
	buffer = append(buffer, answer.RData...)
	return buffer
}

// parseHeader parses the DNS header from a byte slice.
func parseHeader(serializedBuf []byte) DNSHeader {
	buffer := serializedBuf[:12]
	header := DNSHeader{
		ID:      binary.BigEndian.Uint16(buffer[0:2]),
		QR:      buffer[2] >> 7,
		OPCODE:  (buffer[2] >> 3) & 0x0F,
		AA:      (buffer[2] >> 2) & 0x01,
		TC:      (buffer[2] >> 1) & 0x01,
		RD:      buffer[2] & 0x01,
		RA:      buffer[3] >> 7,
		Z:       (buffer[3] >> 4) & 0x07,
		RCODE:   buffer[3] & 0x0F,
		QDCOUNT: binary.BigEndian.Uint16(buffer[4:6]),
		ANCOUNT: binary.BigEndian.Uint16(buffer[6:8]),
		NSCOUNT: binary.BigEndian.Uint16(buffer[8:10]),
		ARCOUNT: binary.BigEndian.Uint16(buffer[10:12]),
	}
	return header
}

// parseLabel parses a DNS label from a byte slice.
func parseLabel(buf []byte, source []byte) string {
	offset := 0
	labels := []string{}
	for {
		if buf[offset] == 0 {
			break
		}
		if (buf[offset]&0xC0)>>6 == 0b11 {
			ptr := int(binary.BigEndian.Uint16(buf[offset:offset+2]) << 2 >> 2)
			length := bytes.Index(source[ptr:], []byte{0})
			labels = append(labels, parseLabel(source[ptr:ptr+length+1], source))
			offset += 2
			continue
		}
		length := int(buf[offset])
		substring := buf[offset+1 : offset+1+length]
		labels = append(labels, string(substring))
		offset += length + 1
	}
	return strings.Join(labels, ".")
}

// parseQuestions parses the DNS questions from a byte slice.
func parseQuestions(serializedBuf []byte, numQues uint16) []DNSQuestion {
	var questionList []DNSQuestion
	offset := 12
	for i := uint16(0); i < numQues; i++ {
		len := bytes.Index(serializedBuf[offset:], []byte{0})
		label := parseLabel(serializedBuf[offset:offset+len+1], serializedBuf)
		questionList = append(questionList, DNSQuestion{
			Name:  label,
			Type:   binary.BigEndian.Uint16(serializedBuf[offset+len+1 : offset+len+3]),
			Class: binary.BigEndian.Uint16(serializedBuf[offset+len+3 : offset+len+5]),
		})
		offset += len + 5
	}
	return questionList
}
