package pinger

import (
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	probing "github.com/prometheus-community/pro-bing"
	"github.com/swagnikdutta/netprobe/pkg/printer"
)

type ProbingPinger struct{}

func (p *ProbingPinger) Ping(hostname string) error {
	pinger, err := probing.NewPinger(hostname)
	if err != nil {
		return errors.Wrapf(err, "error creating pinger instance")
	}

	pinger.Count = 3
	if err := pinger.Run(); err != nil {
		return errors.Wrapf(err, "error running pinger")
	}
	stats := pinger.Statistics()

	headers := []string{"Packets sent", "Packets received", "Packet loss", "IP Address", "Address", "Min rtt", "Max rtt"}
	data := [][]string{
		{
			strconv.Itoa(stats.PacketsSent),
			strconv.Itoa(stats.PacketsRecv),
			strconv.FormatFloat(stats.PacketLoss, 'f', -1, 64),
			bytesToStr(stats.IPAddr.IP),
			stats.Addr,
			stats.MinRtt.String(),
			stats.MaxRtt.String(),
		},
	}
	printPingResults(data, headers)
	return nil
}

func printPingResults(data [][]string, headers []string) {
	p := new(printer.TableWriterPrinter)
	p.PrintTableView(data, headers)
}

func bytesToStr(ip net.IP) string {
	builder := strings.Builder{}
	for i, b := range ip {
		builder.WriteString(strconv.Itoa(int(b)))
		if i < len(ip)-1 {
			builder.WriteByte('.')
		}
	}

	return builder.String()
}
