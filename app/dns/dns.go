package dns

import "encoding/binary"

// Message struct represents a DNS message
type Message struct {
	ID       uint16
	Header   []byte
	Question []byte
	Answer   []byte
	OPCODE   uint16
	RD       bool
}

// NewMessage creates a new DNS message with initialized fields
func NewMessage() *Message {
	return &Message{
		Header:   make([]byte, 12),
		Question: []byte{},
		Answer:   []byte{},
	}
}

// ParseMessage parses the incoming DNS query packet
func ParseMessage(buf []byte) *Message {
	message := NewMessage()
	message.ID = binary.BigEndian.Uint16(buf[0:2])
	message.OPCODE = (binary.BigEndian.Uint16(buf[2:4]) & 0x7800) >> 11
	message.RD = (buf[2] & 0x01) == 1
	return message
}

// SetHeader sets the DNS header fields based on the received message
func (m *Message) SetHeader(request *Message) {
	binary.BigEndian.PutUint16(m.Header[0:2], request.ID) // Mimic the received ID
	m.Header[2] = 1 << 7                                  // QR flag set to 1 (response)
	m.Header[2] |= uint8(request.OPCODE << 3)             // Mimic OPCODE
	if request.RD {
		m.Header[2] |= 1 << 0 // Mimic RD if set
	}
	m.Header[3] = 0 // RA = 0, Z = 0, RCODE = 0

	// Set QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
	binary.BigEndian.PutUint16(m.Header[4:6], 1)
	binary.BigEndian.PutUint16(m.Header[6:8], 1)
	binary.BigEndian.PutUint16(m.Header[8:10], 0)
	binary.BigEndian.PutUint16(m.Header[10:12], 0)
}

// SetQuestion sets the DNS question section
func (m *Message) SetQuestion() {
	m.Question = []byte("\x0ccodecrafters\x02io\x00")
	m.Question = binary.BigEndian.AppendUint16(m.Question, 1) // Type A
	m.Question = binary.BigEndian.AppendUint16(m.Question, 1) // Class IN
}

// SetAnswer sets the DNS answer section
func (m *Message) SetAnswer() {
	answer := []byte("\x0ccodecrafters\x02io\x00")
	answer = binary.BigEndian.AppendUint16(answer, 1)   // Type A
	answer = binary.BigEndian.AppendUint16(answer, 1)   // Class IN
	answer = binary.BigEndian.AppendUint32(answer, 60)  // TTL
	answer = binary.BigEndian.AppendUint16(answer, 4)   // RDLENGTH
	answer = append(answer, []byte{8, 8, 8, 8}...) // RDATA (example IP 8.8.8.8)

	m.Answer = answer
}

// PrepareMessage prepares a DNS response based on the received DNS query
func PrepareMessage(request *Message) *Message {
	message := NewMessage()
	message.SetHeader(request)
	message.SetQuestion()
	message.SetAnswer()
	return message
}
