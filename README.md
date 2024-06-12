<div align="center">

[![GitHub Release][release-img]][release]
[![Test][test-img]][test]
[![Go Report Card][go-report-img]][go-report]
[![License: Apache-2.0][license-img]][license]

</div>

methodaws provides a number of granular AWS enumeration capabilities that can be leveraged by security teams to gain better visibility into their AWS environments.

## Development

methodaws leverages Palantir's [godel](https://github.com/palantir/godel) build tool to provide streamlined Go build infrastructure. After cloning this repository, you can run `./godelw build` to build the project from source.

### Adding a new AWS Enumeration Capability

#### New AWS Resource Type

If you are adding a new AWS resource type to methodaws, you should add it as a new top level command that will get nested under the methodaws root command. To do this, you will do the following:

1. Add a file to `cmd/` that corresponds to the sub-command name you'd like to add to the `methodaws` CLI
2. You can use `cmd/ec2.go` as a template
3. Your file needs to be a member function of the `methodaws` struct and should be of the form `Init<cmd>Command`
4. Add a new member to the `methodaws` struct in `cmd/root.go` that corresponds to your command name.
5. Call your `Init` function from `main.go`
6. Add logic to your commands runtime and put it in its own package within `internal` (e.g., `internal/ec2`)

## Testing

### Testing from Source (pre-build)

You can test locally without building by running

```bash
go run main.go <subcommand> <flags>
```

### Testing the CLI (post-build)

You can test locally using the CLI by building it from source. Run, `./godelw clean && ./godelw build` to clean out the `out/` directory and rebuild. You will now have a binary at `out/build/methodaws/<version>/<architecture>/methodaws` that you can run

The majority of methodaws commands will require authentication with an AWS account, so you will need to have the appropriate [AWS Credentials exported as environment variables](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html).
