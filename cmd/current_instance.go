package cmd

import (
	"github.com/Method-Security/methodaws/internal/current"
	"github.com/spf13/cobra"
)

func (a *MethodAws) InitCurrentInstanceCommand() {
	currentInstanceCmd := &cobra.Command{
		Use:   "current",
		Short: "Describe the current AWS instance",
		Long:  "Describe the current AWS instance",
	}

	describeCmd := &cobra.Command{
		Use:   "describe",
		Short: "Describe the current AWS instance",
		Long:  "Describe the current AWS instance",
		Run: func(cmd *cobra.Command, args []string) {
			report, err := current.InstanceDetails(cmd.Context(), *a.AwsConfig)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	iamCmd := &cobra.Command{
		Use:   "iam",
		Short: "Describe the IAM role of the current AWS instance",
		Long:  "Describe the IAM role of the current AWS instance",
		Run: func(cmd *cobra.Command, args []string) {
			report, err := current.IamDetails(cmd.Context(), *a.AwsConfig)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	currentInstanceCmd.AddCommand(describeCmd)
	currentInstanceCmd.AddCommand(iamCmd)
	a.RootCmd.AddCommand(currentInstanceCmd)
}
