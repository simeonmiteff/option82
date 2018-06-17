package main

import (
	"encoding/json"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/client9/reopen"
	"log"
	"log/syslog"
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
	outFile := flag.String("o", "",
		"Log file (messages go to stdout if absent)")
	enableSyslog := flag.Bool("s", false,
		"Output option 82 data to syslog instead of log file or stdout")

	flag.Parse()

	var handle *pcap.Handle = nil
	var sysLog *syslog.Writer = nil

	if *srcFile != "" && *srcInt != "" {
		log.Fatal("Cannot input from file and network at the same time")
	} else if *srcFile != "" {
		var err error = nil
		handle, err = pcap.OpenOffline(*srcFile)
		if err != nil {
			log.Fatalf("Problem opening pcap file: %s", err)
		}
	} else if *srcInt != "" {
		var err error = nil
		handle, err = pcap.OpenLive(*srcInt, 1600, true, pcap.BlockForever)
		if err != nil {
			log.Fatalf("Problem opening pcap interface: %s", err)
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

	if *enableSyslog {
		var err error = nil
		sysLog, err = syslog.Dial("", "", syslog.LOG_LOCAL0, "option82")
		if err != nil {
			log.Fatalf("Unable to connect to syslog: %s", err)
		}
	}

	// TODO: Should be possible to override BPF rule with a flag
	if err := handle.SetBPFFilter("udp src and dst port 67"); err != nil {
		log.Fatalf("Unable to set BPF: %s", err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			result, hasOption82 := HandlePacket(packet)
			if hasOption82 {
				enc, err := json.Marshal(*result)
				if err != nil {
					log.Fatalf("Could not marshal JSON: %s", err)
				}
				if *enableSyslog {
					sysLog.Info(string(enc))
				} else {
					log.Println(string(enc))
				}

			}
		}
	}
}
