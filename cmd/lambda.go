package cmd

import (
	"github.com/Method-Security/methodaws/internal/lambda"
	"github.com/spf13/cobra"
)

func (a *MethodAws) InitLambdaCommand() {
	lambdaCmd := &cobra.Command{
		Use:   "lambda",
		Short: "Audit Lambda functions",
		Long:  `Audit Lambda functions`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate Lambda functions",
		Long:  `Enumerate Lambda functions`,
		Run: func(cmd *cobra.Command, args []string) {
			report := lambda.EnumerateLambda(cmd.Context(), *a.AwsConfig, a.RootFlags.Regions)
			a.OutputSignal.Content = report
		},
	}

	lambdaCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(lambdaCmd)
}
