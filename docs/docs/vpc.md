# VPC

The `methodaws vpc` family of commands provide information about an account's VPCs.

## Enumerate

The enumerate command will gather information about all of the VPCs that the provided credentials have access to.

### Usage

```bash
methodaws vpc enumerate --region us-east-1 --output json
```

### Help Text

```bash
$ methodaws vpc enumerate -h
Enumerate all VPCs in your AWS account.

Usage:
  methodaws vpc enumerate [flags]

Flags:
  -h, --help   help for enumerate

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -r, --region string        AWS region
  -v, --verbose              Verbose output
```
