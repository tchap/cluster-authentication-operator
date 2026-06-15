The root cause analysis in the previous comment is solid. A few additional observations about the `WellKnownReadyController` retry behavior that compound the problem:

## No backoff between retries

The retry loop in `checkWellknownEndpointReady` ([wellknown_ready_controller.go:266-280](https://github.com/openshift/cluster-authentication-operator/blob/master/pkg/controllers/readiness/wellknown_ready_controller.go#L266-L280)) is a tight `for i := 0; i < 3; i++` with zero delay between attempts. When kube-apiserver is mid-startup after a node reboot, hammering it 3 times in rapid succession with 5s timeouts is essentially the same as trying once with a 15s timeout. Adding a backoff interval (even 1-2 seconds) between retries would meaningfully increase the chance of catching a server that's still coming up.

## Endpoint list is not refreshed between retries

`getAPIServerIPs()` is called once per sync at [line 220](https://github.com/openshift/cluster-authentication-operator/blob/master/pkg/controllers/readiness/wellknown_ready_controller.go#L220), and the resulting list is iterated at [line 225](https://github.com/openshift/cluster-authentication-operator/blob/master/pkg/controllers/readiness/wellknown_ready_controller.go#L225) without re-fetching. During a node reboot, endpoint state changes rapidly. Re-fetching the endpoint list on each retry attempt would allow the controller to pick up the updated state where the rebooting node may no longer be in `NotReadyAddresses` or may have started serving.

Related: the check at [line 390](https://github.com/openshift/cluster-authentication-operator/blob/master/pkg/controllers/readiness/wellknown_ready_controller.go#L390) fails the entire check if *any* `NotReadyAddresses` exist, even if the other nodes are healthy.

## Connection errors get no grace period

As noted in the RCA, HTTP 404 and metadata mismatch are wrapped in `ControllerProgressingError` with a 5-minute grace window before escalating to Degraded ([lines 290, 305](https://github.com/openshift/cluster-authentication-operator/blob/master/pkg/controllers/readiness/wellknown_ready_controller.go#L290-L305)), but connection errors ([line 282-283](https://github.com/openshift/cluster-authentication-operator/blob/master/pkg/controllers/readiness/wellknown_ready_controller.go#L282-L283)) are returned as plain errors, which immediately set `Progressing=True` with no grace. A connection error during a node reboot is at least as transient as a 404.

## Prior work

[PR #855](https://github.com/openshift/cluster-authentication-operator/pull/855) addressed a similar problem in `endpointAccessibleController` by retrying the full fetch-endpoints-and-check cycle with configurable backoff, re-fetching the endpoint list on each attempt. It was closed (the linked bug was for a different controller), but the pattern is directly applicable here.
