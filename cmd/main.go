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
		Short: "network troubleshooting tool",
		Long: `npctl is a CLI application designed to simplify network troubleshooting 
through a suite of natively implemented networking tools`,
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
