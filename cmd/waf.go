package cmd

import (
	// Generated
	wafdefs "github.com/Method-Security/methodaws/generated/go/waf"

	// Internal
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/Method-Security/methodaws/internal/waf"

	// External
	"github.com/spf13/cobra"
)

func (a *MethodAws) InitWAFCommand() {
	// WAF Command
	// Subcommands:
	// - enumerate
	wafCmd := &cobra.Command{
		Use:   "waf",
		Short: "Audit and manage WAFs",
		Long:  `Audit and manage WAFs`,
	}

	// Enumerate command
	enumerateWAF := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate WAFs",
		Long:  `Enumerate WAFs in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Get Account ID
			accountID, err := sts.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config
			config := getWafEnumerateConfig(*accountID, a.RootFlags.Regions)

			// Report
			report := waf.EnumerateWAF(cmd.Context(), *a.AwsConfig, config)
			a.OutputSignal.Content = report
		},
	}

	wafCmd.AddCommand(enumerateWAF)
	a.RootCmd.AddCommand(wafCmd)
}

// getWafEnumerateConfig returns a WafEnumerateConfig with the given accountID and regions
func getWafEnumerateConfig(accountID string, regions []string) wafdefs.WafEnumerateConfig {
	return wafdefs.WafEnumerateConfig{
		AccountId: accountID,
		Regions:   regions,
	}
}
