package cmd

import (
	"github.com/spf13/cobra"
	"gitlab.com/method-security/cyber-tools/methodaws/internal/sts"
)

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
