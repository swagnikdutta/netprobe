package main

import (
	"fmt"
	"log"
	"net"

	"github.com/spf13/cobra"
	"github.com/swagnikdutta/netprobe/pkg/ping"
	"github.com/swagnikdutta/netprobe/pkg/resolver/native-dns"
)

func NewNetProbeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "netprobe host[:port]",
		Short: "Network troubleshooting tool",
		Long: `NetProbe simplifies network troubleshooting for non-experts by providing a user-friendly
command-line tool. With a single command, users can diagnose connectivity issues, ping hosts, 
and gather network information, streamlining the troubleshooting process without requiring 
in-depth networking knowledge`,
		Version: "1.0.0",
		Args:    cobra.ExactArgs(1),
		Example: "netprobe google.com",
		Run:     StartV2,
	}

	cmd.SetHelpFunc(func(cmd *cobra.Command, strings []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "\n%s\n\nUsage:\n  %s\n\nExample:\n  %s\n\n", cmd.Long, cmd.Use, cmd.Example)
	})

	return cmd
}

func StartV2(cmd *cobra.Command, args []string) {
	resolver := new(native_dns.Resolver)
	resolver.Meta.TxnIDMap = make(map[uint16]interface{})
	resolver.Nameserver = net.IP{198, 41, 0, 4}

	host := "www.example.com"
	ip, _ := resolver.ResolveDestination(host)
	fmt.Printf("IP address of %s is: %s", host, ip.String())
}

// Start starts the network troubleshooting steps
func Start(cmd *cobra.Command, args []string) {
	host := args[0]
	pinger := ping.NewPinger()
	if err := pinger.Ping(host); err != nil {
		log.Printf("error pinging host: %v", err)
	}
}

func main() {
	cmd := NewNetProbeCommand()
	if err := cmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %s", err)
	}
}
