package dns

import (
	"encoding/binary"
	"strings"
)

type Message struct {
	Header   []byte
	Question []byte
	Answer   []byte
	ID       uint16
	QR       uint8
	OPCODE   uint8
	RD       uint8
	RCODE    uint8
	QName    string
	QType    uint16
	QClass   uint16
}

func NewMessage() *Message {
	return &Message{
		Header:   make([]byte, 12),
		Question: []byte{},
		Answer:   []byte{},
	}
}

func ParseMessage(data []byte) *Message {
	message := NewMessage()

	message.ID = binary.BigEndian.Uint16(data[0:2])
	message.QR = data[2] >> 7
	message.OPCODE = (data[2] >> 3) & 0xF
	message.RD = (data[2] >> 1) & 0x1

	qdCount := binary.BigEndian.Uint16(data[4:6])

	if qdCount > 0 {
		offset := 12
		message.QName, offset = parseQName(data, offset)
		message.QType = binary.BigEndian.Uint16(data[offset : offset+2])
		message.QClass = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		message.Question = data[12 : offset+4]
	}

	if message.OPCODE == 0 {
		message.RCODE = 0
	} else {
		message.RCODE = 4
	}

	return message
}

func parseQName(data []byte, offset int) (string, int) {
	name := ""
	for {
		length := int(data[offset])
		if length == 0 {
			break
		}
		if len(name) > 0 {
			name += "."
		}
		name += string(data[offset+1 : offset+1+length])
		offset += length + 1
	}
	return name, offset + 1
}

func PrepareMessage(req *Message) []byte {
	resp := NewMessage()

	resp.ID = req.ID
	resp.QR = 1
	resp.OPCODE = req.OPCODE
	resp.RD = req.RD
	resp.RCODE = req.RCODE

	resp.SetHeader()
	resp.Question = req.Question
	resp.SetAnswer(req.QName)

	response := []byte{}
	response = append(response, resp.Header...)
	response = append(response, resp.Question...)
	response = append(response, resp.Answer...)

	return response
}

func (m *Message) SetHeader() {
	binary.BigEndian.PutUint16(m.Header[0:2], m.ID)
	m.Header[2] = m.QR<<7 | m.OPCODE<<3 | m.RD<<1
	m.Header[3] = m.RCODE
	binary.BigEndian.PutUint16(m.Header[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(m.Header[6:8], 1) // ANCOUNT
	binary.BigEndian.PutUint16(m.Header[8:10], 0)
	binary.BigEndian.PutUint16(m.Header[10:12], 0)
}

func (m *Message) SetAnswer(qname string) {
	answer := []byte{}
	answer = append(answer, encodeQName(qname)...)
	answer = binary.BigEndian.AppendUint16(answer, 1)       // Type A
	answer = binary.BigEndian.AppendUint16(answer, 1)       // Class IN
	answer = binary.BigEndian.AppendUint32(answer, 60)      // TTL 60 seconds
	answer = binary.BigEndian.AppendUint16(answer, 4)       // Length
	answer = binary.BigEndian.AppendUint32(answer, 0x08080808) // IP 8.8.8.8

	m.Answer = answer
}

func encodeQName(qname string) []byte {
	encoded := []byte{}
	parts := strings.Split(qname, ".")
	for _, part := range parts {
		encoded = append(encoded, byte(len(part)))
		encoded = append(encoded, []byte(part)...)
	}
	encoded = append(encoded, 0)
	return encoded
}
