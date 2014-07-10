package main

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"github.com/tealeg/xlsx"
	"os"
	"os/exec"
	"strings"
	"time"
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

func nmapCommand(ipaddr string, tcpPorts string, udpPorts string) (out []byte) {

	//  nmap -p $PORTS -sU -sT -d --max-retries 8 --append-output -oX $LOG_GNMAP
	ports := fmt.Sprintf("T:%s,U:%s", tcpPorts, udpPorts)

	out, err := exec.Command("sudo", "nmap", ipaddr, "-p", ports, "-sU", "-sT", "-d", "--append-output", "--max-retries", "8", "-oX", "-").Output()

	if err != nil {
		fmt.Printf("ERROR: %v", out)
	}

	return out
}

func report(data []byte, writer *csv.Writer) {
	report := Report{}
	err := xml.Unmarshal([]byte(data), &report)

	//fmt.Printf("%s", &report)

	if err != nil {
		panic(err)
	}
	
	i := 1
	for _, host := range report.Host {
		ipReport := []string{host.Address.Addr}

		for _, port := range host.Ports {
			//fmt.Printf("- %d\t%s\t%s\t%s\n", port.PortID, port.Service.Name, port.Service.Product, port.Service.Version)
			ipReport = append(ipReport, port.State.State)
		}
		writer.Write(ipReport)
		writer.Flush()

		err := writer.Error()
		if err != nil {
			fmt.Printf("%v", err)
		}

		fmt.Printf("\n")
		i++
	}
}

func main() {
	excelFileName := "iplist.xlsx"
	excelFile, error := xlsx.OpenFile(excelFileName)
	if error != nil {
		fmt.Printf("Ensure the file %v exists\n", excelFileName)
		os.Exit(0)
	}

	tcpPorts := "21,22,23,25,80,102,104,111,135,137,400,401,402,443,502,545,771,777,808,1023,1025,1026,1027,1029,1089,1090,1091,1101,1217,1330,1331,1332,1433,1883,2074,2075,2076,2077,2078,2079,2101,2102,2222,2223,2308,2323,2404,2700,2947,3060,3250,3306,3389,3622,4120,4121,4122,4123,4124,4125,4241,4242,4322,4410,4445,4446,4502,4503,4592,4840,4843,5000,5159,5241,5413,5450,5457,5458,5481,5500,5501,5502,5503,5504,5505,5506,5507,5508,5509,5560,5800,5900,6002,6543,7579,7580,7600,7700,7710,7720,7721,7722,7723,8080,8081,8083,8087,8443,9001,9090,9111,9999,10110,10651,12233,12293,12299,12397,12399,12401,14000,18245,18246,19999,20000,20222,21379,27017,28017,34962,34963,34964,38080,40000,44818,46822,46823,46824,47808,49281,50523,50777,54321,57176,58723,60093"

	udpPorts := "22,23,67,68,69,104,111,123,135,137,161,502,1023,1089,1090,1091,1883,2101,2102,2222,3306,3389,3622,4840,4843,5000,10110,10260,11234,17185,20034,28017,34962,34963,34964,40000,44818,47808,48899,55000,55001,55002,55003"

	file, error := os.OpenFile("output_"+fmt.Sprintf("%v", int32(time.Now().Unix()))+".csv", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)

	if error != nil {
		panic(error)
	}
	defer file.Close()

	header := []string{"address"}

	for _, port := range strings.Split(tcpPorts, ",") {
		header = append(header, fmt.Sprintf("tcp/%v", port))
	}

	for _, port := range strings.Split(udpPorts, ",") {
		header = append(header, fmt.Sprintf("udp/%v", port))
	}

	// New Csv writer
	writer := csv.NewWriter(file)

	writer.Write(header) // converts array of string to comma seperated values for 1 row.
	writer.Flush()

	for _, sheet := range excelFile.Sheets {
		i := 0
		for _, row := range sheet.Rows {
			for _, cell := range row.Cells {
				ipaddr := cell.String()
				fmt.Printf("%s: %v of %v\n", ipaddr, i+1, len(sheet.Rows))

				out := nmapCommand(strings.Trim(ipaddr, "  "), tcpPorts, udpPorts)
				report(out, writer)

				i++
			}
		}
	}
}
