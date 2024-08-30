package main

import (
	"fmt"
	"net"
	"flag"
	"os"
	"github.com/codecrafters-io/dns-server-starter-go/app/dns" 
)

func main() {

	// Parse the resolver address from the command-line arguments
	resolver := flag.String("resolver", "", "The address of the DNS resolver in the form <ip>:<port>")
	flag.Parse()

	if *resolver == "" {
		fmt.Println("Usage: ./your_server --resolver <address>")
		os.Exit(1)
	}


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

		fmt.Printf("Received %d bytes from %s\n", size, source)
		
		// response := dns.CreateNewDnsMessage(buf[:size]) // Call the function from the dns package

		// Forward the DNS query to the specified resolver
		response, err := dns.ForwardQuery(buf[:size], *resolver)
		if err != nil {
			fmt.Println("Failed to forward query:", err)
			continue
		}

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
