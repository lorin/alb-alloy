---
---

# Todo

[] Target
[] Condition

# Modeling AWS Application Load Balancers in Alloy

I've always found the configuration details for AWS [application load balancers][alb-intro] confusing.
This makes it an excellent candidate for modeling in [Alloy][alloy-docs].

This file can be loaded into the Alloy Analyzer.

I'm going to annotate my model with comments that are copy-pasted from the [ALB docs][alb-intro].



```alloy
open util/ordering[Priority]

// A load balancer serves as the single point of contact for clients
sig LoadBalancer {
	//  You add one or more listeners to your load balancer.
	listeners: set Listener
} {
	// The docs don't specify this, but presumably the listeners have to be on different ports
	no disj l1, l2: listeners | l1.port=l2.port
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

abstract sig Protocol {}
one sig HTTP, HTTPS extends Protocol {}
sig Port {}
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

sig StatusCode {}
sig ContentType {}
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

// In the API, this is modeled as an integer that represents the duration in secodns
// We don't model that here, though
sig Duration {}
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

one sig HTTP_301, HTTP_302 extends StatusCode {}

sig HostName {}
sig Path {}
sig Query {}

sig Condition {}

```

# Target gtoups

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
	// Considerations for the gRPC protocol version
	(protocolVersion = GRPC) => {
		// The only supported listener protocol is HTTPS.
		protocol = HTTPS
		// The only supported action type for listener rules is forward.
		// The model already enforces this, because you can only specify a target group with a forward rule

		// The only supported target types are instance and ip.
		targetType in Instance+IP

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
		targetType in Instance+IP
	}
}

abstract sig TargetType {}

// The targets are specified by instance ID.
sig Instance extends TargetType {}

// The targets are IP addresses
// For restrictions by CIDR block, see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html#target-type
sig IP extends TargetType {}

// The target is a Lambda function.
sig Lambda extends TargetType {}

abstract sig IpAddressType {}
one sig IPv4, IPv6 extends IpAddressType {}

sig Target {}

// Health checks are performed on all targets registered to a target group that is specified in a listener rule for your load balancer.
sig HealthCheck {}

// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html#target-group-protocol-version
abstract sig ProtocolVersion {}
one sig HTTP1_1, HTTP2, GRPC extends ProtocolVersion {}

```

The docs say:

> You can register a target with multiple target groups.

We don't actually have to do anything in our Alloy model to permit this.

## Running the model

```alloy
fact "no unowned entities of interest" {
	all l: Listener | some listeners.l
}

run { one LoadBalancer }
```


[alb-intro]: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html
[alloy-docs]: https://alloy.readthedocs.io/en/latest/
[listener-rules]: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#listener-rules
