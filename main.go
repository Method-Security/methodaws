package main

import (
	"flag"
	"os"

	"gitlab.com/method-security/cyber-tools/methodaws/cmd"
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

	if err := methodaws.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
