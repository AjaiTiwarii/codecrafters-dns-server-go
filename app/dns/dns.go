package dns

import "encoding/binary"

type Message struct {
	Header   []byte
	Questions [][]byte
	Answers  [][]byte
	RD       uint16
	Opcode   uint16
	ID       uint16
	Rcode    uint16
}

func NewMessage() *Message {
	return &Message{
		Header:   make([]byte, 12),
		Questions: [][]byte{},
		Answers:  [][]byte{},
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
			question, newOffset := parseQuestion(request, offset)
			message.Questions = append(message.Questions, question)
			offset = newOffset
		}
	}

	return message
}

func parseQuestion(request []byte, offset int) ([]byte, int) {
	question := []byte{}
	startOffset := offset
	for {
		labelLength := int(request[offset])
		if labelLength == 0 {
			offset++
			break
		}

		if (labelLength & 0xC0) == 0xC0 { // Check if it's a pointer
			pointerOffset := int(binary.BigEndian.Uint16(request[offset:offset+2]) & 0x3FFF)
			compressedPart, _ := parseQuestion(request, pointerOffset)
			question = append(question, compressedPart...)
			offset += 2
			break
		} else {
			offset++
			question = append(question, request[startOffset:offset+labelLength]...)
			offset += labelLength
		}
	}
	
	// Append Type and Class fields
	question = append(question, request[offset:offset+4]...)
	return question, offset + 4
}


func PrepareMessage(request *Message) []byte {
	response := NewMessage()
	response.ID = request.ID
	response.RD = request.RD
	response.Opcode = request.Opcode
	response.Rcode = request.Rcode

	response.SetHeader(len(request.Questions))
	response.SetQuestions(request.Questions)
	response.SetAnswers(request.Questions)

	return append(response.Header, flatten(append(response.Questions, response.Answers...))...)
}

func (m *Message) SetHeader(qdCount int) {
	binary.BigEndian.PutUint16(m.Header[0:2], m.ID)

	flags := combineFlags(1, m.Opcode, 0, 0, m.RD, 0, 0, m.Rcode)
	binary.BigEndian.PutUint16(m.Header[2:4], flags)

	binary.BigEndian.PutUint16(m.Header[4:6], uint16(qdCount)) // QDCOUNT: number of questions
	binary.BigEndian.PutUint16(m.Header[6:8], uint16(qdCount)) // ANCOUNT: number of answers
	binary.BigEndian.PutUint16(m.Header[8:10], 0)              // NSCOUNT
	binary.BigEndian.PutUint16(m.Header[10:12], 0)             // ARCOUNT
}

func (m *Message) SetQuestions(questions [][]byte) {
	m.Questions = questions
}

func (m *Message) SetAnswers(questions [][]byte) {
	for _, question := range questions {
		answer := []byte{}
		answer = append(answer, question...)

		answer = binary.BigEndian.AppendUint16(answer, 1) // Type A
		answer = binary.BigEndian.AppendUint16(answer, 1) // Class IN
		answer = binary.BigEndian.AppendUint32(answer, 60) // TTL: 60 seconds
		answer = binary.BigEndian.AppendUint16(answer, 4)  // RDLENGTH: 4 bytes
		answer = binary.BigEndian.AppendUint32(answer, binary.BigEndian.Uint32([]byte("\x08\x08\x08\x08"))) // RDATA: 8.8.8.8

		m.Answers = append(m.Answers, answer)
	}
}

func flatten(sections [][]byte) []byte {
	var result []byte
	for _, section := range sections {
		result = append(result, section...)
	}
	return result
}

func combineFlags(qr, opcode, aa, tc, rd, ra, z, rcode uint16) uint16 {
	return uint16(qr<<15 | opcode<<11 | aa<<10 | tc<<9 | rd<<8 | ra<<7 | z<<4 | rcode)
}