# API Gateway

methodaws provides the capability to enumerate AWS API Gateway resources across both v1 (REST API) and v2 (HTTP API) versions.

## Usage
```bash
methodaws api-gateway [command]
```

## Commands

### Enumerate

#### Usage
```bash
methodaws api-gateway enumerate --regions <regions>
```

### Aliases

The `api-gateway` command can also be invoked using the alias `agw`:

```bash
methodaws agw enumerate --regions <regions>
```

## Examples

```bash
# Enumerate API Gateway resources in us-east-1
methodaws api-gateway enumerate --regions us-east-1

# Enumerate API Gateway resources in multiple regions
methodaws api-gateway enumerate --regions us-east-1 --regions us-west-2

# Enumerate API Gateway resources in all regions (default behavior)
methodaws api-gateway enumerate
```

## Resources Enumerated

The API Gateway enumerate command gathers information about:

- REST APIs (API Gateway v1)
- HTTP APIs (API Gateway v2)
- API Gateway configurations and settings
- Associated resources and metadata

By default, both v1 (REST API) and v2 (HTTP API) versions are enumerated to provide comprehensive coverage of your API Gateway infrastructure.

## Output

The output includes detailed information about your API Gateway resources in the specified output format (signal, json).
