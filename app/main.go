package main

import (
	"fmt"
	"net"
	"flag"
	"github.com/codecrafters-io/dns-server-starter-go/app/dns" 
)

func main() {
	ns := flag.String("resolver", "", "Resolver address")
	flag.Parse()

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

	var resolver *net.Resolver
	if len(*ns) != 0 {
		resolver = newResolver(*ns)
	}

	buf := make([]byte, 512)
	
	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}
		msg, err := dns.NewDNSMessage(buf[:size])
		if err != nil {
			fmt.Println("Error parsing incoming message:", err)
			break
		}
		
		response, err := dns.Handle(resolver, msg)
		if err != nil {
			fmt.Printf("Fail to handle request: %v", err)
			break
		}
		_, err = udpConn.WriteToUDP(response.AsBytes(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
			break
		}
	}
}
