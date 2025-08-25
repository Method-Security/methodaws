package cmd

import (
	// Generated
	// Internal
	"github.com/Method-Security/methodaws/internal/route53"
	"github.com/spf13/cobra"
)

// InitRoute53Command initializes the `methodaws route53` subcommand that deals with enumerating Route53 resources.
func (a *MethodAws) InitRoute53Command() {
	//route53Cmd
	//Subcommands:
	// - enumerate
	route53Cmd := &cobra.Command{
		Use:   "route53",
		Short: "Enumerate Route53 resources",
		Long:  `Enumerate Route53 resources`,
	}

	// enumerateCmd
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate Route53 records",
		Long:  `Enumerate Route53 records`,
		Run: func(cmd *cobra.Command, args []string) {

			// Get Report
			report, err := route53.EnumerateRoute53(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Add Commands
	route53Cmd.AddCommand(enumerateCmd)

	a.RootCmd.AddCommand(route53Cmd)
}
