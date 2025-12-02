# EKS

The `methodaws eks` family of commands provide information about an account's EKS clusters and Kubernetes credentials.

## Enumerate

The enumerate command will gather information about all of the EKS clusters that the provided credentials have access to.

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
  -o, --output string         Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string    Path to output file. If blank, will output to STDOUT
  -q, --quiet                 Suppress output
  -r, --regions stringArray   AWS Regions to search for resources. You can specify multiple regions by providing the flag multiple times. If blank, will search all regions.
  -v, --verbose               Verbose output
```

## Creds

The creds command generates Kubernetes credentials for an EKS cluster, allowing you to connect to and manage the cluster with kubectl or other Kubernetes tools.

### Usage

```bash
methodaws eks creds --regions us-east-1 --name <cluster-name> --output json
```

### Help Text

```bash
$ methodaws eks creds -h
Generate a K8s Credential for an EKS instance

Usage:
  methodaws eks creds [flags]

Flags:
  -h, --help          help for creds
      --name string   Name of the EKS cluster

Global Flags:
  -o, --output string         Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string    Path to output file. If blank, will output to STDOUT
  -q, --quiet                 Suppress output
  -r, --regions stringArray   AWS Regions to search for resources. You can specify multiple regions by providing the flag multiple times. If blank, will search all regions.
  -v, --verbose               Verbose output
```
