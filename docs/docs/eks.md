# EKS

The `methodaws eks` family of commands provide information about an account's EKS clusters.

## Enumerate

The enumerate command will gather information about all of the EKS clsuters that the provided credentials have access to.

### Usage

```bash
methodaws eks enumerate --regions us-east-1 --output json

```

### Help Text

```bash
$ methodaws eks enumerate -h
Enumerate EKS instances

Usage:
  methodaws eks enumerate [flags]

Flags:
  -h, --help   help for enumerate

Global Flags:
  -o, --output string          Output format (signal, json). Default value is signal (default "signal")
  -f, --output-file string     Path to output file. If blank, will output to STDOUT
  -q, --quiet                  Suppress output
  -r, --regions stringArray    AWS Regions to search for resources. You can specify multiple regions by providing the flag multiple times. If blank, will search all regions.
  -v, --verbose                Verbose output
```
