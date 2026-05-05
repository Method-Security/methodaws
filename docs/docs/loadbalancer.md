# Load Balancer

methodaws provides the capability to enumerate AWS Load Balancers including both Classic Load Balancers (v1) and Application/Network Load Balancers (v2).

## Usage
```bash
methodaws load-balancer [command]
```

## Commands

### Enumerate

#### Usage
```bash
methodaws load-balancer enumerate --regions <regions> --versions <versions>
```

## Examples

```bash
# Enumerate all load balancer types in us-east-1
methodaws load-balancer enumerate --regions us-east-1

# Enumerate only Application/Network Load Balancers (v2)
methodaws load-balancer enumerate --regions us-east-1 --versions V2

# Enumerate only Classic Load Balancers (v1)
methodaws load-balancer enumerate --regions us-east-1 --versions V1

# Enumerate specific versions in multiple regions
methodaws load-balancer enumerate --regions us-east-1 --regions us-west-2 --versions V1 --versions V2
```

## Flags

### --versions

Specify which load balancer versions to enumerate:
- `V1`: Classic Load Balancers (ELB)
- `V2`: Application Load Balancers (ALB) and Network Load Balancers (NLB)

**Default:** `["V1", "V2"]` (both versions)

## Resources Enumerated

The Load Balancer enumerate command gathers information about:

### Classic Load Balancers (V1)
- Load balancer configurations
- Listeners and health checks
- Instance registrations
- Security groups
- Subnets and availability zones

### Application/Network Load Balancers (V2)
- Load balancer configurations
- Target groups and targets
- Listeners and rules
- Health check configurations
- Security groups and subnets
- Access logs configuration

## Output

The output includes detailed information about your load balancers and their configurations in the specified output format (signal, json).

## Security Considerations

When enumerating load balancers, methodaws will collect:
- Security group associations
- SSL/TLS certificate information
- Target health status
- Network configuration details
