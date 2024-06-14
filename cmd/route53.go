package cmd

import (
	"github.com/Method-Security/methodaws/internal/route53"
	"github.com/spf13/cobra"
)

// Initialize the `methodaws route53` subcommand that deals with enumerating Route53 resources.
func (a *MethodAws) InitRoute53Command() {
	a.Route53Cmd = &cobra.Command{
		Use:   "route53",
		Short: "Enumerate Route53 resources",
		Long:  `Enumerate Route53 resources`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate Route53 records",
		Long:  `Enumerate Route53 records`,
		Run: func(cmd *cobra.Command, args []string) {
			report, err := route53.EnumerateRoute53(cmd.Context(), *a.AwsConfig)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	a.Route53Cmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(a.Route53Cmd)
}
