package cmd

import (
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/spf13/cobra"
)

// InitStsCommand initializes the `methodaws ec2` subcommand that is responsible for interacting with the AWS STS service.
func (a *MethodAws) InitStsCommand() {
	stsCmd := &cobra.Command{
		Use:   "sts",
		Short: "Leverage STS to manage temporary credentials",
		Long:  "Leverage STS to manage temporary credentials",
	}

	arnCmd := &cobra.Command{
		Use:   "arn",
		Short: "Get the caller ARN",
		Long:  "Get the caller ARN",
		Run: func(cmd *cobra.Command, args []string) {
			arn, err := sts.GetCallerArn(cmd.Context(), *a.AwsConfig)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = arn
		},
	}

	stsCmd.AddCommand(arnCmd)
	a.RootCmd.AddCommand(stsCmd)
}
