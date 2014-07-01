package main

import (
	"fmt"
	"encoding/xml"
	"github.com/tealeg/xlsx"
	"os/exec"
)

type Verbose struct {
	Level string `xml:"level,attr"`
}

type PortState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type PortService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	Extra   string `xml:"extrainfo,attr"`
}

type Host struct {
	StartTime string     `xml:"starttime,attr"`
	Address   Address    `xml:"address"`
	Hostnames []Hostname `xml:"hostnames>hostname"`
	Ports     []Port     `xml:"ports>port"`
	OS        []OS       `xml:"os"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Level    string `xml:"level,attr"`
}

type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type Port struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   uint        `xml:"portid,attr"`
	State    PortState   `xml:"state"`
	Service  PortService `xml:"service"`
}

type Class struct {
	Type     string `xml:"type,attr"`
	Vendor   string `xml:"vendor,attr"`
	Family   string `xml:"osfamily,attr"`
	Gen      string `xml:"osgen,attr"`
	Accuracy uint   `xml:"accuracy,attr"`
}

type Match struct {
	Name     string `xml:"name,attr"`
	Accuracy uint   `xml:"accuracy,attr"`
}


type OS struct {
	Match Match `xml:"osmatch"`
	Class Class `xml:"osclass"`
}

type Report struct {
	XMLName  xml.Name `xml:"nmaprun"`
	Scanner  string   `xml:"scanner,attr"`
	Args     string   `xml:"args,attr"`
	Verbose  Verbose  `xml:"verbose"`
	Start    uint64   `xml:"start,attr"`
	StartStr string   `xml:"startstr,attr"`
	Host     []Host   `xml:"host"`
}

func nmapCommand(ipaddr string) (out []byte) {

	//  nmap -p $PORTS -sU -sT -d --max-retries 8 --append-output -oX $LOG_GNMAP
	out, err := exec.Command("sudo", "nmap", ipaddr, "-p", "T:21,22,23,25,80,102,104,111,135,137,400,401,402,443,502,545,771,777,808,1023,1025,1026,1027,1029,1089,1090,1091,1101,1217,1330,1331,1332,1433,1883,2074,2075,2076,2077,2078,2079,2101,2102,2222,2223,2308,2323,2404,2700,2947,3060,3250,3306,3389,3622,4120,4121,4122,4123,4124,4125,4241,4242,4322,4410,4445,4446,4502,4503,4592,4840,4843,5000,5159,5241,5413,5450,5457,5458,5481,5500,5501,5502,5503,5504,5505,5506,5507,5508,5509,5560,5800,5900,6002,6543,7579,7580,7600,7700,7710,7720,7721,7722,7723,8080,8081,8083,8087,8443,9001,9090,9111,9999,10110,10651,12233,12293,12299,12397,12399,12401,14000,18245,18246,19999,20000,20222,21379,27017,28017,34962,34963,34964,38080,40000,44818,46822,46823,46824,47808,49281,50523,50777,54321,57176,58723,60093,U:22,23,67,68,69,104,111,123,135,137,161,502,1023,1089,1090,1091,1883,2101,2102,2222,3306,3389,3622,4840,4843,5000,10110,10260,11234,17185,20034,28017,34962,34963,34964,40000,44818,47808,48899,55000,55001,55002,55003", "-sU", "-sT", "-d", "-oX", "-").Output()

	if err != nil {
		fmt.Printf("ERROR: %v", out)
	}

	return out
}

func report(data []byte) {
	report := Report{}
	err := xml.Unmarshal([]byte(data), &report)

	if err != nil {
		panic(err)
	}
	fmt.Printf("Report for: %s (%s)\n\n", &report.Args, report.StartStr)

	for _, host := range report.Host {
		fmt.Printf("%s\n", host.Address.Addr)

		oports := []Port{}

		for _, port := range host.Ports {
			if port.State.State == "open" {
				oports = append(oports, port)
			}
		}

		if len(oports) > 0 {
			fmt.Printf("Open ports:\n")
			for _, port := range oports {
				fmt.Printf("- %d\t%s\t%s\t%s\n", port.PortID, port.Service.Name, port.Service.Product, port.Service.Version)
			}
		} else {
			fmt.Printf("No open ports.\n")
		}

		if len(host.OS) > 0 {
			fmt.Printf("Matching OSes:\n")
			for _, osm := range host.OS {
				fmt.Printf("- %s / %s / %s (%d%%)\n", osm.Class.Family, osm.Class.Vendor, osm.Class.Type, osm.Class.Accuracy)
			}
		}

		fmt.Printf("\n")
	}
}

func main() {
	excelFileName := "iplist.xlsx"
	xlFile, error := xlsx.OpenFile(excelFileName)
	if error != nil {
		fmt.Printf("%v", error)
	}
	for _, sheet := range xlFile.Sheets {
		fmt.Printf("-------- %v -------- \n", sheet.Name)

		for _, row := range sheet.Rows {
			for _, cell := range row.Cells {
				ipaddr := cell.String()
				fmt.Printf("%s: \n", ipaddr)

				out := nmapCommand(ipaddr)
				report(out)
			}
		}
	}
}
