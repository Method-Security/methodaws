package cmd

import (
	"github.com/spf13/cobra"
	"gitlab.com/method-security/cyber-tools/methodaws/internal/eks"
)

func (a *MethodAws) InitEksCommand() {
	eksCmd := &cobra.Command{
		Use:   "eks",
		Short: "Enumerate EKS instances",
		Long:  `Enumerate EKS instances`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate EKS instances",
		Long:  `Enumerate EKS instances`,
		Run: func(cmd *cobra.Command, args []string) {
			report, err := eks.EnumerateEks(cmd.Context(), *a.AwsConfig)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	eksCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(eksCmd)
}
