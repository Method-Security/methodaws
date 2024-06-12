package cmd

import (
	"github.com/spf13/cobra"
	"gitlab.com/method-security/cyber-tools/methodaws/internal/iam"
)

func (a *MethodAws) InitIamCommand() {
	iamCmd := &cobra.Command{
		Use:   "iam",
		Short: "Audit and command IAM resources",
		Long:  `Audit and command IAM resources`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate IAM resources",
		Long:  `Enumerate IAM resources`,
		Run: func(cmd *cobra.Command, args []string) {
			report, err := iam.EnumerateIamRoles(cmd.Context(), *a.AwsConfig)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	iamCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(iamCmd)
}
