package main

import (
	"flag"
	"os"

	"github.com/Method-Security/methodaws/cmd"
)

var Version = "none"

func main() {
	flag.Parse()

	methodaws := cmd.NewMethodAws(Version)
	methodaws.InitRootCommand()

	methodaws.InitAPIGatewayCommand()
	methodaws.InitCurrentInstanceCommand()
	methodaws.InitEc2Command()
	methodaws.InitEksCommand()
	methodaws.InitIamCommand()
	methodaws.InitLambdaCommand()
	methodaws.InitLoadBalancerCommand()
	methodaws.InitRdsCommand()
	methodaws.InitRoute53Command()
	methodaws.InitS3Command()
	methodaws.InitSecurityGroupCommand()
	methodaws.InitStsCommand()
	methodaws.InitVPCCommand()
	methodaws.InitWAFCommand()
	methodaws.InitCloudFrontCommand()
	methodaws.InitElasticBeanstalkCommand()

	if err := methodaws.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
