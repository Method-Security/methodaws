package cmd

import (
	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/Method-Security/methodaws/internal/loadbalancer"
	"github.com/spf13/cobra"
)

func (a *MethodAws) InitLoadBalancerCommand() {
	loadBalancerCmd := &cobra.Command{
		Use:     "loadbalancer",
		Short:   "Audit and manage load balancers",
		Long:    `Audit and manage load balancers`,
		Aliases: []string{"lb"},
	}

	var loadBalancerVersions string
	enumerate := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate load balancers",
		Long:  `Enumerate load balancers in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			if loadBalancerVersions != "all" && loadBalancerVersions != "v1" && loadBalancerVersions != "v2" {
				errorMessage := "Invalid load balancer version. Valid options are ['all', 'v1', 'v2']"
				a.OutputSignal.Status = 1
				a.OutputSignal.ErrorMessage = &errorMessage
				return
			}

			report := methodaws.LoadBalancerReport{
				Errors:          []string{},
				V2LoadBalancers: []*methodaws.LoadBalancerV2{},
				V1LoadBalancers: []*methodaws.LoadBalancerV1{},
			}

			if loadBalancerVersions == "all" || loadBalancerVersions == "v1" {
				v1Report := loadbalancer.EnumerateV1ELBs(cmd.Context(), *a.AwsConfig)
				report.V1LoadBalancers = v1Report.V1LoadBalancers
				report.AccountId = v1Report.AccountId
				report.Errors = append(report.Errors, v1Report.Errors...)
			}
			if loadBalancerVersions == "all" || loadBalancerVersions == "v2" {
				v2Report := loadbalancer.EnumerateV2LBs(cmd.Context(), *a.AwsConfig)
				report.V2LoadBalancers = v2Report.V2LoadBalancers
				report.AccountId = v2Report.AccountId
				report.Errors = append(report.Errors, v2Report.Errors...)
			}

			a.OutputSignal.Content = report
		},
	}

	enumerate.Flags().StringVar(&loadBalancerVersions, "versions", "all", "Load balancer versions to enumerate. Valid options are ['all', 'v1', 'v2']. Default value is 'all'")

	loadBalancerCmd.AddCommand(enumerate)
	a.RootCmd.AddCommand(loadBalancerCmd)
}
