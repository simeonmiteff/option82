package main

import (
	"bytes"
	"fmt"
	"net"

	"encoding/binary"
	"encoding/hex"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SuboptionType is one of ~13 defined sub-options for DHCP option 82
type SuboptionType byte

// Suboption is the binary structure for DHCP option 82
type Suboption struct {
	Type   SuboptionType
	Length uint8
	Data   []byte
}

// CiscoStructuredAgentCircuitID is used by Cisco switches
type CiscoStructuredAgentCircuitID struct {
	VLAN   uint16
	Module uint8
	Port   uint8
}

const (
	SuboptionTypeAgentCircuitID                      SuboptionType = 1
	SuboptionTypeAgentRemoteID                       SuboptionType = 2
	SuboptionTypeDOCSISDeviceClass                   SuboptionType = 4
	SuboptionTypeLinkSelection                       SuboptionType = 5
	SuboptionTypeSubscriberID                        SuboptionType = 6
	SuboptionTypeRADIUSAttributes                    SuboptionType = 7
	SuboptionTypeAuthentication                      SuboptionType = 8
	SuboptionTypeVendorSpecificInformation           SuboptionType = 9
	SuboptionTypeRelayAgentFlags                     SuboptionType = 10
	SuboptionTypeServerIdentifierOverride            SuboptionType = 11
	SuboptionTypeDHCPv4VirtualSubnetSelection        SuboptionType = 151
	SuboptionTypeDHCPv4VirtualSubnetSelectionControl SuboptionType = 152
)

// SubOptionTypeString maps SuboptionType numbers to meaningful text strings.
func SubOptionTypeString(t SuboptionType) string {
	switch t {
	case SuboptionTypeAgentCircuitID:
		return "Agent-Circuit-ID"
	case SuboptionTypeAgentRemoteID:
		return "Agent-Remote-ID"
	case SuboptionTypeDOCSISDeviceClass:
		return "DOCSIS-Device-Class"
	case SuboptionTypeLinkSelection:
		return "Link-Selection"
	case SuboptionTypeSubscriberID:
		return "Subscriber-ID"
	case SuboptionTypeRADIUSAttributes:
		return "RADIUS-Attributes"
	case SuboptionTypeAuthentication:
		return "Authentication"
	case SuboptionTypeVendorSpecificInformation:
		return "Vendor-Specific-Information"
	case SuboptionTypeRelayAgentFlags:
		return "Relay-Agent-Flags"
	case SuboptionTypeServerIdentifierOverride:
		return "Server-Identifier-Override"
	case SuboptionTypeDHCPv4VirtualSubnetSelection:
		return "DHCPv4-Virtual-Subnet-Selection"
	case SuboptionTypeDHCPv4VirtualSubnetSelectionControl:
		return "DHCPv4-Virtual-Subnet-Selection-Control"
	default:
		return "Unknown-Suboption"
	}
}

// isPrintableCharacterString check if >70% of the string is
// comprised of printable characters. It returns stats and the check's result.
func isPrintableCharacterString(b []byte) (uint, uint, bool) {
	if len(b) == 8 && b[0] == 0 && b[1] == 6 {
		return 0, 0, false
	}
	// TODO: is 70% a robust threshold?
	var thresh uint = uint(float32(len(b)) * 0.7)
	var score uint = 0
	for _, c := range b {
		if c > 0x1f {
			score++
		}
	}
	return score, thresh, score >= thresh
}

// toHex returns a Suboption's Data field as a hex string
func toHex(o Suboption) string {
	return fmt.Sprintf("%v", hex.EncodeToString(o.Data))
}

// PopulateMap is a member of Suboption that populates the  referenced map
// with (k,v) pairs for the useful information stored in the suboption. It
// attempts to handle known vendor binary structures (or strings), and fails
// back to hex strings if it can't figure out what it is looking at.
func (o Suboption) PopulateMap(work map[string]interface{}) {
	_, _, printable := isPrintableCharacterString(o.Data)
	result := make(map[string]interface{})
	work[SubOptionTypeString(o.Type)] = result
	if !printable {
		switch o.Type {
		case SuboptionTypeAgentCircuitID:
			if o.Data[0] == 0 && o.Data[1] == 4 {
				buf := &bytes.Buffer{}
				buf.Write(o.Data[2:])
				var c CiscoStructuredAgentCircuitID
				err := binary.Read(buf, binary.BigEndian, &c)
				if err != nil {
					panic(err)
				}
				result["option_structure"] = "cisco_vlan_mod_port"
				result["cisco_vlan_mod_port"] = c
			} else if o.Data[0] == 1 {
				// TODO: do we care about the string length in o.Data[1],
				// or just use the remainder of the bytes?
				result["option_structure"] = "cisco_string"
				result["cisco_string"] = string(o.Data[1:])
			} else {
				result["option_structure"] = "unknown_hex_values"
				result["unknown_hex_values"] = toHex(o)
			}
		case SuboptionTypeAgentRemoteID:
			if o.Data[0] == 0 && o.Data[1] == 6 {
				var mac net.HardwareAddr = o.Data[2:]
				result["option_structure"] = "cisco_switch_base_mac"
				result["cisco_switch_base_mac"] = fmt.Sprintf("%v", mac)
			} else if o.Data[0] == 1 {
				result["option_structure"] = "cisco_string"
				result["cisco_string"] = string(o.Data[1:])
			} else {
				result["option_structure"] = "unknown_hex_values"
				result["unknown_hex_values"] = toHex(o)
			}
		default:
			result["option_structure"] = "unknown_hex_values"
			result["unknown_hex_values"] = toHex(o)
		}
	} else {
		result["option_structure"] = "generic_string"
		result["generic_string"] = string(o.Data[:])
	}
}

// HandlePacket takes a gopacket.Packet that is expected to contain a DHCPv4
// packet and tries to extract option 82 information into a map, which it
// returns along with a bool that indicates whether it found option 82.
// It also includes the client MAC and IP (if not zero) and the requested
// hostname and IP options sent by the DHCP client.
func HandlePacket(packet gopacket.Packet) (*map[string]interface{}, bool) {
	dhcp, ok := packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	result := make(map[string]interface{})
	hasOption82 := false
	if ok && dhcp.Operation == 1 {
		for _, opt := range dhcp.Options {
			if opt.Type == 82 {
				hasOption82 = true
				break
			}

		}
		if hasOption82 {
			var mac net.HardwareAddr = dhcp.ClientHWAddr
			var ip net.IP = dhcp.ClientIP
			result["client_mac"] = fmt.Sprintf("%v", mac)
			if !ip.Equal(net.IPv4(0, 0, 0, 0)) {
				result["client_ip"] = fmt.Sprintf("%v", ip)
			}
			for _, opt := range dhcp.Options {
				if opt.Type == 82 {
					o := Suboption{}
					var index uint8 = 0
					for index < uint8(len(opt.Data))-1 {
						o.Type = SuboptionType(opt.Data[index])
						o.Length = opt.Data[index+1]
						o.Data = opt.Data[index+2 : index+o.Length+2]
						if o.Length == 0 {
							break
						} else {
							index = index + o.Length + 2
						}
						o.PopulateMap(result)
					}
				} else if opt.Type == layers.DHCPOptHostname {
					result["client_request_hostname"] = string(opt.Data[:])
				} else if opt.Type == layers.DHCPOptRequestIP {
					result["client_request_ip"] = fmt.Sprintf("%v",
						net.IPv4(opt.Data[0], opt.Data[1], opt.Data[2],
							opt.Data[3]))
				}
			}
		}
	}
	return &result, hasOption82
}
