---
---

# Todo

[x] Healthchecks
[] Security group
[] Target
[] Condition
[] Constraints on actions

# Modeling AWS Application Load Balancers in Alloy

I've always found the configuration details for AWS [application load balancers][alb-intro] confusing.
This makes it an excellent candidate for modeling in [Alloy][alloy-docs].

This file can be loaded into the Alloy Analyzer.

I'm going to annotate my model with comments that are copy-pasted from the [ALB docs][alb-intro].


## Preamble

```alloy
open util/ordering[Priority]
```

## Basics

Here are some common models we're going to need.
Note that Alloy doesn't require us to specify them before they are used.


```alloy
// In the API, this is modeled as an integer that represents the duration in secodns
// We just model it as "duration"
sig Duration {}


abstract sig Protocol {}
one sig HTTP, HTTPS extends Protocol {}

sig Port {}

abstract sig IpAddressType {}
one sig IPv4, IPv6 extends IpAddressType {}


// Note that we only explicitly model the 301 and 302 codes.
sig StatusCode {}
one sig HTTP_301, HTTP_302 extends StatusCode {}

sig ContentType {}
sig HostName {}
sig Path {}
sig Query {}
```

## Security group


<https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html>

```alloy

// True if src is allowed to reach dest on port
pred allows[source : set SecurityGroup, dest : set SecurityGroup, port: Port] {
	port in (source.outbound.ports & dest.inbound.ports)
}

sig SecurityGroup {
	inbound: set SecurityGroupRule,
	outbound: set SecurityGroupRule
}

sig SecurityGroupRule {
	protocol: SecurityGroupProtocol,
	ports: set Port,
	// source for inbound, dest for outbound
	// We aren't modeling prefix lists here
	traffic: IPv4Address+IPv6Address+IPv4Range+IPv6Range+SecurityGroup
}

sig IPv4Address  {}
sig IPv6Address  {}
sig IPv4Range {
	addresses: set IPv4Address
}
sig IPv6Range {
	address: set IPv6Address
}


sig SecurityGroupProtocol {}
one sig TCP extends SecurityGroupProtocol {}
```


## Load balancer

```alloy
// A load balancer serves as the single point of contact for clients
sig LoadBalancer {
	//  You add one or more listeners to your load balancer.
	listeners: set Listener,
	securityGroups: set SecurityGroup,
} {
	// The docs don't specify this, but presumably the listeners have to be on different ports
	no disj l1, l2: listeners | l1.port=l2.port

	// The rules for the security groups that are associated with your load balancer must allow traffic in both directions on both the listener and the health check ports.

	// Allow inbound access to the listener
	all l: Listener | some s : securityGroups | {
		l.port in s.inbound.ports
	}


	// Allow the load balancer to hit the instance listener

	// All target groups associated with security groups
	all target : (listeners.rules.actions[univ]).groups.targets & (Instance+IP) |
			 // the port that the listener is trying to forward to allows access from the security group assocaited with the load balancer
		allows[securityGroups, target.@securityGroups, target.port]
}


// A listener checks for connection requests from clients, using the protocol and port that you configure.
sig Listener {
	// A listener is configured for a specific protocol and prot
	protocol: Protocol,
	port: Port,

	// The rules that you define for a listener determine how the load balancer routes requests to its registered targets.
	rules: set Rule,
	// You must define a default rule for each listener
	default: Rule,

} {
	// the default listener rule is one of the rules
	default in rules
}

```

## Rules

[Listener rule docs][listener-rules]


```alloy

//  Each rule consists of a priority, one or more actions, and one or more conditions.
sig Rule {
	// Each rule has a priority
	priority: Priority,
	actions: seq Action,
	conditions: set Condition
} {
	// Each rule must include exactly one of the following actions: forward, redirect, or fixed-response
	// and it must be the last action to be performed.
	some s: univ.actions | {
		s in Forward+Redirect+FixedResponse
		no (univ.actions -s ) & Forward+Redirect+FixedResponse
		s = actions.last
	}
}

// Rules are evaluated in priority order, from the lowest value to the highest value. The default rule is evaluated last.
fact "Default rule is evaluated last" {
	all rule : Listener.default | rule.priority = last
}
sig Priority {}
```

## Actions

```alloy
abstract sig Action {}

sig AuthenticateCognito, AuthenticateOidc extends Action {}
```


### Fixed response

<https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#fixed-response-actions>

```alloy
sig FixedResponse extends Action {
	statusCode: StatusCode,
	contentType: ContentType,
	messageBody: MessageBody
}

sig MessageBody {}
```

### Forward actions

<https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#forward-actions>

```alloy

//
sig Forward extends Action {
	groups: set TargetGroup,
	weights: Weight->groups,

	// sticky sessions are optionally configured.
	// If enabled, specify a duration
	// For more details on stickiness, see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/sticky-sessions.html
	stickiness: lone Duration
}

//  Each target group weight is a value from 0 to 999
// We don't model the weights explicitly here.
sig Weight {}

```

```alloy
// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#redirect-actions
// Redirect target: protocol://hostname:port/path?query
sig Redirect extends Action {
	statusCode: HTTP_301+HTTP_302,
	protocol: Protocol,
	hostname: HostName,
	port: Port,
	path: Path,
	query: Query
}


sig Condition {}

```

# Target groups

<https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html>

```alloy

// Each target group routes requests to one or more registered targets, such as EC2 instances, using the protocol and port number that you specify.
sig TargetGroup {
	protocol: Protocol,
	port: Port,

	targetType: TargetType,
	ipAddressType: IpAddressType,


	targets: set Target,
	// You can configure health checks on a per target group basis.
	healthChecks: set HealthCheck,

	protocolVersion: ProtocolVersion
} {
	// Targets have to match the type
	(targetType = InstanceType) => targets in Instance
	(targetType = IpType) => targets in IP
	(targetType = LambdaType) => {
		targets in Lambda
		// For lambdas, only one target
		one targets
	}

	// Considerations for the gRPC protocol version
	(protocolVersion = GRPC) => {
		// The only supported listener protocol is HTTPS.
		protocol = HTTPS
		// The only supported action type for listener rules is forward.
		// The model already enforces this, because you can only specify a target group with a forward rule

		// The only supported target types are instance and ip.
		targetType in InstanceType+IpType

		// You cannot use Lambda functions as targets.
		// This sounds redundant with the one above
	}

  // Considerations for the HTTP/2 protocol version
	(protocolVersion = HTTP2) => {
		// The only supported listener protocol is HTTPS.
		protocol = HTTPS
		// The only supported action type for listener rules is forward.
		// The model already enforces this, because you can only specify a target group with a forward rule

		// The only supported target types are instance and ip.
		targetType in InstanceType+IpType
	}


}

abstract sig TargetType {}

// The targets are specified by instance ID.
sig InstanceType extends TargetType {}

// The targets are IP addresses
// For restrictions by CIDR block, see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html#target-type
sig IpType extends TargetType {}

// The target is a Lambda function.
sig LambdaType extends TargetType {}

// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html#target-group-protocol-version
abstract sig ProtocolVersion {}
one sig HTTP1_1, HTTP2, GRPC extends ProtocolVersion {}

```

## Targets

<https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-register-targets.html>


```alloy
abstract sig Target {}
abstract sig SecurityGroupTarget extends Target {
	securityGroups: set SecurityGroup
}

sig Instance, IP extends SecurityGroupTarget {}


// Lambdas don't use security groups for access permissions, they use a different mechanism, see:
// https://docs.aws.amazon.com/lambda/latest/dg/services-alb.html
sig Lambda extends Target {}
```


## Health checks

<https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-health-checks.html>


```alloy
// Health checks are performed on all targets registered to a target group that is specified in a listener rule for your load balancer.

sig HealthCheck {
	protocol: Protocol,
	port: Port,

  // Confusingly, a "path" in the redirect actions is separate from the query: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#redirect-actions
	// Here, the path includes the query, so we use a different model
	path: HealthCheckPath,
	timeout: Duration,
	interval: Duration,
	healthyThreshold: Count,
	UnhealthyThreshold: Count,
	// The codes to use when checking for a successful response from a target. These are called Success codes in the console.
	matcher: set StatusCode
}

sig HealthCheckPath {
	path: Path,
	query: lone Query
}

// Model of an integer count
sig Count {}
```

## Autoscaling group

Interestingly, you don't add an autoscaling group to a load balancer.
Instead, you add a load balancer to an autoscaling group.
Presumably, the ASG service is responsible for adding and removing targets to/from the load balancer's target group.

```alloy
sig AutoScalingGroup {
	instances: set Instance,
	securityGroups: set SecurityGroup,
	loadBalancer: lone LoadBalancer,
	targetGroup: lone TargetGroup,
	targetGroupState : TargetGroupState

} {
	// All of the instances have the same security group configuration
	all i : instances | securityGroups = i.@securityGroups

	// if the ASG is associated with a load balancer, it is associated with a target group
	some loadBalancer => some targetGroup
}

// https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_LoadBalancerTargetGroupState.html
abstract sig TargetGroupState {}
one sig Adding, Added, InService, Removing, Removed extends TargetGroupState {}
```


## Running the model


```alloy
fact "no unowned entities of interest" {
	all l: Listener | some listeners.l
	all t: TargetGroup | some f : Forward | t in f.groups
	all action : Action | some rule : Rule | action in rule.actions[univ]
	all h : HealthCheck | some t: TargetGroup  | h in t.healthChecks
}

run { one LoadBalancer }
```


[alb-intro]: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html
[alloy-docs]: https://alloy.readthedocs.io/en/latest/
[listener-rules]: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#listener-rules
