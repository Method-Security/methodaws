# Current Instance Command

The `methodaws current` family of commands are intended to be used if you find yourself on a machine that you are unsure is an AWS VM or not. It provides a suite of capabilities and diagnostics related to the current instance, and whether or not it is part of AWS.

## Describe Current Instance

If used from an AWS EC2 instance, this command will gather information from the AWS Instance Metadata endpoint about the host, including private and public IP addresses and hostnames associated with the machine.

### Usage

```bash
methodaws current describe
```

### Help Text

```bash
$ methodaws current describe --help
Describe the current AWS instance

Usage:
  methodaws current describe [flags]

Flags:
  -h, --help   help for describe

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -r, --region string        AWS region
  -v, --verbose              Verbose output
```

## Describe Current Instance IAM Roles

If used from an AWS EC2 instance, this command will gather information about any and all AWS IAM Roles that are attached to the endpoint. Information about IAM Policies that are attached to the Roles will be included as well, providing you with a complete picture of the host's permissions.

### Usage

```bash
methodaws current iam
```

### Help Text

```bash
$ methodaws current iam --help
Describe the IAM role of the current AWS instance

Usage:
  methodaws current iam [flags]

Flags:
  -h, --help   help for iam

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -r, --region string        AWS region
  -v, --verbose              Verbose output
```
