package loadbalancer

import (
	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

func convertTargetGroupType(targetType types.TargetTypeEnum) methodaws.TargetType {
	switch targetType {
	case types.TargetTypeEnumInstance:
		return methodaws.TargetTypeInstance
	case types.TargetTypeEnumIp:
		return methodaws.TargetTypeIp
	case types.TargetTypeEnumLambda:
		return methodaws.TargetTypeLambda
	default:
		return methodaws.TargetTypeInstance
	}
}

func convertTargetGroupIPAddressType(ipAddressType types.TargetGroupIpAddressTypeEnum) methodaws.TargetGroupIpAddressType {
	switch ipAddressType {
	case types.TargetGroupIpAddressTypeEnumIpv4:
		return methodaws.TargetGroupIpAddressTypeIpv4
	case types.TargetGroupIpAddressTypeEnumIpv6:
		return methodaws.TargetGroupIpAddressTypeIpv6
	default:
		return methodaws.TargetGroupIpAddressTypeIpv4
	}
}

func convertIPAddressType(ipAddressType types.IpAddressType) methodaws.IpAddressType {
	switch ipAddressType {
	case types.IpAddressTypeIpv4:
		return methodaws.IpAddressTypeIpv4
	case types.IpAddressTypeDualstack:
		return methodaws.IpAddressTypeDualstack
	case types.IpAddressTypeDualstackWithoutPublicIpv4:
		return methodaws.IpAddressTypeDualstackWithoutPublicIpv4
	default:
		return methodaws.IpAddressTypeIpv4
	}
}

func loadBalancerCodeToState(code *types.LoadBalancerState) *methodaws.LoadBalancerState {
	var state methodaws.LoadBalancerState
	switch code.Code {
	case types.LoadBalancerStateEnumActive:
		state = methodaws.LoadBalancerStateActive
	case types.LoadBalancerStateEnumProvisioning:
		state = methodaws.LoadBalancerStateProvisioning
	case types.LoadBalancerStateEnumActiveImpaired:
		state = methodaws.LoadBalancerStateActiveImpaired
	case types.LoadBalancerStateEnumFailed:
		state = methodaws.LoadBalancerStateFailed
	default:
		return nil
	}
	return &state
}

func convertProtocol(protocol types.ProtocolEnum) *methodaws.Protocol {
	var methodProtocol methodaws.Protocol
	switch protocol {
	case types.ProtocolEnumHttp:
		methodProtocol = methodaws.ProtocolHttp
	case types.ProtocolEnumHttps:
		methodProtocol = methodaws.ProtocolHttps
	case types.ProtocolEnumTcp:
		methodProtocol = methodaws.ProtocolTcp
	case types.ProtocolEnumTls:
		methodProtocol = methodaws.ProtocolTls
	case types.ProtocolEnumUdp:
		methodProtocol = methodaws.ProtocolUdp
	default:
		return nil
	}
	return &methodProtocol
}

func convertProtocolFromString(protocol *string) *methodaws.Protocol {
	if protocol == nil {
		return nil
	}

	var methodProtocol methodaws.Protocol

	switch *protocol {
	case "HTTP":
		methodProtocol = methodaws.ProtocolHttp
	case "HTTPS":
		methodProtocol = methodaws.ProtocolHttps
	case "TCP":
		methodProtocol = methodaws.ProtocolTcp
	case "TLS":
		methodProtocol = methodaws.ProtocolTls
	default:
		return nil
	}

	return &methodProtocol
}
