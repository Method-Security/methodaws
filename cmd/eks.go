package cmd

import (
	"github.com/Method-Security/methodaws/internal/eks"
	"github.com/spf13/cobra"
)

// InitEksCommand initializes the `methodaws eks` subcommand that deals with enumerating EKS instances and their
// related resources.
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

	credsCmd := &cobra.Command{
		Use:   "creds",
		Short: "Generate a K8s Credential for an EKS instance",
		Long:  `Generate a K8s Credential for an EKS instance`,
		Run: func(cmd *cobra.Command, args []string) {
			clusterName, err := cmd.Flags().GetString("name")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report, err := eks.CredsEks(cmd.Context(), *a.AwsConfig, clusterName)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	credsCmd.Flags().String("name", "", "Name of the EKS instance")

	eksCmd.AddCommand(enumerateCmd)
	eksCmd.AddCommand(credsCmd)
	a.RootCmd.AddCommand(eksCmd)
}
