# VPC

The `methodaws vpc` family of commands provide information about an account's VPCs.

## Usage
```bash
methodaws vpc [command]
```

## Commands

### Enumerate

The enumerate command will gather information about all of the VPCs that the provided credentials have access to.

#### Usage

```bash
methodaws vpc enumerate --regions us-east-1 --output json
```

#### Help Text

```bash
$ methodaws vpc enumerate -h
Enumerate all VPCs in your AWS account.

Usage:
  methodaws vpc enumerate [flags]

Flags:
  -h, --help   help for enumerate

Global Flags:
  -o, --output string          Output format (signal, json). Default value is signal (default "signal")
  -f, --output-file string     Path to output file. If blank, will output to STDOUT
  -q, --quiet                  Suppress output
  -r, --regions stringArray    AWS Regions to search for resources. You can specify multiple regions by providing the flag multiple times. If blank, will search all regions.
  -v, --verbose                Verbose output
```
