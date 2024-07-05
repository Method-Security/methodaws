package main

import (
	"flag"
	"os"

	"github.com/Method-Security/methodaws/cmd"
)

var version = "none"

func main() {
	flag.Parse()

	methodaws := cmd.NewMethodAws(version)
	methodaws.InitRootCommand()
	methodaws.InitEc2Command()
	methodaws.InitS3Command()
	methodaws.InitEksCommand()
	methodaws.InitRdsCommand()
	methodaws.InitRoute53Command()
	methodaws.InitCurrentInstanceCommand()
	methodaws.InitStsCommand()
	methodaws.InitIamCommand()
	methodaws.InitSecurityGroupCommand()
	methodaws.InitVPCCommand()
	methodaws.InitLoadBalancerCommand()

	if err := methodaws.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
