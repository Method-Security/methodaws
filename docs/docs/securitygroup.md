# Security Groups

The `methodaws securitygroup` family of commands provide information about an account's EC2 instances.

## Enumerate

The enumerate command will gather information about all of the Security Groups that the provided credentials have access to.

### Usage

```bash
methodaws securitygroup enumerate --region us-east-1 --output json
```

```bash
methodaws sg enumerate --region us-east-1 --output json
```

### Help Text

```bash
$ methodaws securitygroup enumerate -h
Enumerate security groups

Usage:
  methodaws securitygroup enumerate [flags]

Flags:
  -h, --help         help for enumerate
      --vpc string   VPC ID to filter security groups by

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -r, --region string        AWS region
  -v, --verbose              Verbose output
```
