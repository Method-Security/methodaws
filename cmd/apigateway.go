package cmd

import (
	"github.com/Method-Security/methodaws/internal/apigateway"
	"github.com/spf13/cobra"
)

func (a *MethodAws) InitAPIGatewayCommand() {
	apiGatewayCmd := &cobra.Command{
		Use:     "apigateway",
		Short:   "Audit and manage api gateways",
		Long:    `Audit and manage api gateways`,
		Aliases: []string{"agw"},
	}

	enumerate := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate api gateways",
		Long:  `Enumerate api gateways in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			report, err := apigateway.EnumerateAPIGateway(cmd.Context(), *a.AwsConfig, a.RootFlags.Regions)
			if err != nil {
				a.OutputSignal.AddError(err)
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	apiGatewayCmd.AddCommand(enumerate)
	a.RootCmd.AddCommand(apiGatewayCmd)
}
