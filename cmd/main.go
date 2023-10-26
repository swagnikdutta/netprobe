package main

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/swagnikdutta/netprobe/pkg/ping"
	native_dns "github.com/swagnikdutta/netprobe/pkg/resolver/native-dns"
)

func NewNetProbeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "npctl",
		Short: "Network troubleshooting tool",
		Long: `NetProbe simplifies network troubleshooting for non-experts by providing a user-friendly
command-line tool. With a single command, users can diagnose connectivity issues, ping hosts, 
and gather network information, streamlining the troubleshooting process without requiring 
in-depth networking knowledge`,
		Version: "1.0.0",
	}

	return cmd
}

func main() {
	rootCmd := NewNetProbeCommand()
	rootCmd.AddCommand(ping.NewPingCommand(), native_dns.NewDigCommand())
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %s", err)
	}
}
