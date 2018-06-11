package main

import (
	"encoding/json"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/client9/reopen"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// The option82 program reads DHCPv4 packets via libpcap (network or file input)
// and ouputs JSON strings to a log file or to Stdout containing fields that
// should aid network troubelshooting, incident handling, or forensics.
func main() {
	srcFile := flag.String("f", "", "PCAP input file")
	srcInt := flag.String("i", "", "Capture interface")
	outFile := flag.String("o", "", "Output log file (goes to stdout if absent)")

	flag.Parse()

	var handle *pcap.Handle = nil

	if *srcFile != "" && *srcInt != "" {
		panic("Cannot input from file and network at the same time")
	} else if *srcFile != "" {
		var err error = nil
		handle, err = pcap.OpenOffline(*srcFile)
		if err != nil {
			panic(err)
		}
	} else if *srcInt != "" {
		var err error = nil
		handle, err = pcap.OpenLive(*srcInt, 1600, true, pcap.BlockForever)
		if err != nil {
			panic(err)
		}
	} else {
		flag.Usage()
		log.Println("Aborting: you must specify -i XOR -f")
		os.Exit(1)
	}

	if *outFile != "" {
		f, err := reopen.NewFileWriter(*outFile)
		if err != nil {
			log.Fatalf("Unable to set output log: %s", err)
		}
		log.SetOutput(f)
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		go func() {
			for {
				<-sighup
				log.Println("Got a sighup, reopening log file.")
				f.Reopen()
			}
		}()
	} else {
		// Output to Stdout seems more useful if not logging to file.
		log.SetOutput(os.Stdout)
	}

	// TODO: Should be possible to override BPF rule with a flag
	if err := handle.SetBPFFilter("udp src and dst port 67"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			result, hasOption82 := HandlePacket(packet)
			if hasOption82 {
				enc, err := json.Marshal(*result)
				if err != nil {
					panic(err)
				}
				log.Println(string(enc))
			}
		}
	}
}
