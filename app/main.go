package main

import (
	
	"fmt"
	"net"
	"encoding/binary"
	"github.com/codecrafters-io/dns-server-starter-go/app/dns"

)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	// Uncomment this block to pass the first stage
	
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}
	
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()
	
	buf := make([]byte, 512)
	
	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}
	
		// Extract header fields from the received DNS packet
		id := binary.BigEndian.Uint16(buf[0:2])
		opcode := (buf[2] >> 3) & 0x0F
		rd := (buf[2] >> 0) & 0x01

		fmt.Printf("Received %d bytes from %s: ID=%d OPCODE=%d RD=%d\n", size, source, id, opcode, rd)

		// Prepare the DNS response message using the extracted fields
		message := dns.PrepareMessage(id, 1, uint16(opcode), uint16(rd))

		response := []byte{}
		response = append(response, message.Header...)
		response = append(response, message.Question...)
		response = append(response, message.Answer...)

	
		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
