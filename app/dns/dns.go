package dns

import "encoding/binary"

type Message struct {
	Header   []byte
	Question []byte
	Answer   []byte
	RD       uint16
	Opcode   uint16
	ID       uint16
	Rcode    uint16
}

func NewMessage() *Message {
	return &Message{
		Header:   make([]byte, 12),
		Question: []byte{},
		Answer:   []byte{},
	}
}

func ParseMessage(request []byte) *Message {
	message := NewMessage()
	message.ID = binary.BigEndian.Uint16(request[0:2])

	// Extract flags
	flags := binary.BigEndian.Uint16(request[2:4])
	if((flags & (1 << 8)) != 0){
		message.RD = 1
	}else{
		message.RD = 0
	}
	message.Opcode = (flags >> 11) & 0xF

	// Determine Rcode based on Opcode
	if message.Opcode == 0 {
		message.Rcode = 0 // No error for standard query
	} else {
		message.Rcode = 4 // Not implemented for other Opcodes
	}

	// Copy the question section
	qdCount := binary.BigEndian.Uint16(request[4:6])
	offset := 12
	if qdCount > 0 {
		for i := 0; i < int(qdCount); i++ {
			// Assuming only one question section and copying it directly
			nameEnd := offset
			for request[nameEnd] != 0 {
				nameEnd++
			}
			nameEnd++ // Include the null byte

			message.Question = append(message.Question, request[offset:nameEnd]...)
			message.Question = binary.BigEndian.AppendUint16(message.Question, 1) // Type A
			message.Question = binary.BigEndian.AppendUint16(message.Question, 1) // Class IN
			offset = nameEnd + 4
		}
	}

	return message
}

func PrepareMessage(request *Message) []byte {
	response := NewMessage()
	response.ID = request.ID
	response.RD = request.RD
	response.Opcode = request.Opcode
	response.Rcode = request.Rcode

	response.SetHeader()
	response.SetQuestion(request.Question)
	response.SetAnswer(request.Question)

	return append(response.Header, append(response.Question, response.Answer...)...)
}

func (m *Message) SetHeader() {
	binary.BigEndian.PutUint16(m.Header[0:2], m.ID)

	flags := combineFlags(1, m.Opcode, 0, 0, m.RD, 0, 0, m.Rcode)
	binary.BigEndian.PutUint16(m.Header[2:4], flags)

	binary.BigEndian.PutUint16(m.Header[4:6], 1) // QDCOUNT: 1 question
	binary.BigEndian.PutUint16(m.Header[6:8], 1) // ANCOUNT: 1 answer
	binary.BigEndian.PutUint16(m.Header[8:10], 0) // NSCOUNT
	binary.BigEndian.PutUint16(m.Header[10:12], 0) // ARCOUNT
}

func (m *Message) SetQuestion(question []byte) {
	m.Question = question
}

func (m *Message) SetAnswer(question []byte) {
	answer := []byte{}
	answer = append(answer, question...)

	answer = binary.BigEndian.AppendUint16(answer, 1) // Type A
	answer = binary.BigEndian.AppendUint16(answer, 1) // Class IN
	answer = binary.BigEndian.AppendUint32(answer, 60) // TTL: 60 seconds
	answer = binary.BigEndian.AppendUint16(answer, 4)  // RDLENGTH: 4 bytes
	answer = binary.BigEndian.AppendUint32(answer, binary.BigEndian.Uint32([]byte("\x08\x08\x08\x08"))) // RDATA: 8.8.8.8

	m.Answer = answer
}

func combineFlags(qr, opcode, aa, tc, rd, ra, z, rcode uint16) uint16 {
	return uint16(qr<<15 | opcode<<11 | aa<<10 | tc<<9 | rd<<8 | ra<<7 | z<<4 | rcode)
}
