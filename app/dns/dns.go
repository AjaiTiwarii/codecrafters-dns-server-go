package dns

import "encoding/binary"

type Message struct{
	Header []byte
	Question []byte

	//Answer
	//Authority
	//Additional
}

func NewMessage() *Message{
	return &Message{
		Header: make([]byte, 12),
		Question: []byte{},
	}
}

func (m *Message) SetHeader() {
	binary.BigEndian.PutUint16((*m).Header[0:2], 1234)
	binary.BigEndian.PutUint16((*m).Header[2:4], combineFlags(1,0,0,0,0,0,0,0))
	binary.BigEndian.PutUint16((*m).Header[4:6], 1)
	binary.BigEndian.PutUint16((*m).Header[6:8], 0)
	binary.BigEndian.PutUint16((*m).Header[8:10], 0)
	binary.BigEndian.PutUint16((*m).Header[10:12], 0)
}

func (m *Message) SetQuestion(){
	(*m).Question = []byte("\x0ccodecrafters\x02io\x00")
	(*m).Question = binary.BigEndian.AppendUint16((*m).Question, 1)
	(*m).Question = binary.BigEndian.AppendUint16((*m).Question, 1)
}

func PrepareMessage() *Message {
	message := NewMessage()
	message.SetHeader()
	message.SetQuestion()

	return message
}

func combineFlags(qr, opcode, aa, tc, rd, ra, z, rcode uint) uint16 {
	return uint16(qr<<15 | opcode<<11 | aa<<10 | tc<<9 | rd<<8 | ra<<7 | z<<4 | rcode)
}