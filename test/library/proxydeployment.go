package library

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
	"k8s.io/utils/ptr"
)

const (
	squidImage       = "docker.io/ubuntu/squid:latest"
	squidPort        = int32(3128)
	squidServiceName = "squid-proxy"
	squidConfig      = `http_port 3128
acl all src all
http_access allow all
access_log stdio:/dev/stdout
cache_log stdio:/dev/stderr
cache deny all
buffered_logs off
`
)

// CheckFeatureGateEnabledOrSkip skips the test if the specified feature gate
// is not enabled on the cluster.
func CheckFeatureGateEnabledOrSkip(t testing.TB, configClient *configclient.Clientset, featureGateName configv1.FeatureGateName) {
	ctx := context.TODO()

	featureGates, err := configClient.ConfigV1().FeatureGates().Get(ctx, "cluster", metav1.GetOptions{})
	require.NoError(t, err)

	if len(featureGates.Status.FeatureGates) != 1 {
		t.Fatalf("multiple feature gate versions detected — cluster may be upgrading")
		return
	}

	for _, gate := range featureGates.Status.FeatureGates[0].Enabled {
		if gate.Name == featureGateName {
			t.Logf("feature gate %s is enabled", featureGateName)
			return
		}
	}

	t.Skipf("skipping: feature gate %s is not enabled", featureGateName)
}

// DeploySquidProxy deploys a Squid forward proxy in a new test namespace and
// returns the in-cluster proxy URL, the namespace name, and a cleanup function.
func DeploySquidProxy(t testing.TB, kubeClient kubernetes.Interface) (proxyURL, namespace string, cleanup func()) {
	ctx := context.TODO()

	namespace = NewTestNamespaceBuilder("e2e-proxy-").
		WithBaselinePSaEnforcement().
		WithLabels(CAOE2ETestLabels()).
		Create(t, kubeClient.CoreV1().Namespaces())

	cleanup = func() {
		if err := kubeClient.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{}); err != nil {
			t.Logf("error cleaning up proxy namespace %s: %v", namespace, err)
		}
	}

	defer func() {
		if t.Failed() {
			cleanup()
		}
	}()

	_, err := kubeClient.CoreV1().ConfigMaps(namespace).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "squid-config"},
		Data:       map[string]string{"squid.conf": squidConfig},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:   squidServiceName,
			Labels: map[string]string{"app": squidServiceName},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": squidServiceName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": squidServiceName},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "squid",
							Image: squidImage,
							Ports: []corev1.ContainerPort{
								{ContainerPort: squidPort, Protocol: corev1.ProtocolTCP},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "squid-config",
									MountPath: "/etc/squid/squid.conf",
									SubPath:   "squid.conf",
								},
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt32(squidPort),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       5,
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "squid-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "squid-config",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	_, err = kubeClient.AppsV1().Deployments(namespace).Create(ctx, deployment, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = kubeClient.CoreV1().Services(namespace).Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   squidServiceName,
			Labels: map[string]string{"app": squidServiceName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": squidServiceName},
			Ports: []corev1.ServicePort{
				{
					Name:       "proxy",
					Port:       squidPort,
					TargetPort: intstr.FromInt32(squidPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Logf("waiting for squid proxy deployment in %s to be ready", namespace)
	timeLimitedCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	_, err = watchtools.UntilWithSync(timeLimitedCtx,
		cache.NewListWatchFromClient(
			kubeClient.AppsV1().RESTClient(), "deployments", namespace,
			fields.OneTermEqualSelector("metadata.name", squidServiceName)),
		&appsv1.Deployment{},
		nil,
		func(event watch.Event) (bool, error) {
			d := event.Object.(*appsv1.Deployment)
			return d.Status.ReadyReplicas > 0, nil
		},
	)
	require.NoError(t, err)

	proxyURL = fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", squidServiceName, namespace, squidPort)
	t.Logf("squid proxy deployed at %s", proxyURL)
	return proxyURL, namespace, cleanup
}

// DeployProxyNetworkPolicies creates NetworkPolicies that simulate a disconnected
// environment. Auth namespaces are blocked from reaching the Keycloak namespace
// directly — only egress through the proxy namespace on port 3128 is allowed.
// Returns a cleanup function that removes all created policies.
func DeployProxyNetworkPolicies(t testing.TB, kubeClient kubernetes.Interface, proxyNamespace, keycloakNamespace string) func() {
	ctx := context.TODO()

	authNamespaces := []string{
		"openshift-authentication",
		"openshift-authentication-operator",
	}

	var cleanups []func()

	for _, ns := range authNamespaces {
		policyName := fmt.Sprintf("proxy-e2e-deny-direct-%s", ns)

		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      policyName,
				Namespace: ns,
				Labels:    CAOE2ETestLabels(),
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"kubernetes.io/metadata.name": proxyNamespace,
									},
								},
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": squidServiceName},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: squidPort},
								Protocol: protocolPtr(corev1.ProtocolTCP),
							},
						},
					},
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
								Protocol: protocolPtr(corev1.ProtocolUDP),
							},
							{
								Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
								Protocol: protocolPtr(corev1.ProtocolTCP),
							},
						},
					},
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 6443},
								Protocol: protocolPtr(corev1.ProtocolTCP),
							},
						},
					},
				},
			},
		}

		_, err := kubeClient.NetworkingV1().NetworkPolicies(ns).Create(ctx, policy, metav1.CreateOptions{})
		require.NoError(t, err)
		t.Logf("created NetworkPolicy %s in %s", policyName, ns)

		capturedNS, capturedName := ns, policyName
		cleanups = append(cleanups, func() {
			if err := kubeClient.NetworkingV1().NetworkPolicies(capturedNS).Delete(ctx, capturedName, metav1.DeleteOptions{}); err != nil {
				t.Logf("error cleaning up NetworkPolicy %s/%s: %v", capturedNS, capturedName, err)
			}
		})
	}

	keycloakPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "proxy-e2e-allow-only-from-proxy",
			Namespace: keycloakNamespace,
			Labels:    CAOE2ETestLabels(),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": proxyNamespace,
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := kubeClient.NetworkingV1().NetworkPolicies(keycloakNamespace).Create(ctx, keycloakPolicy, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Logf("created NetworkPolicy proxy-e2e-allow-only-from-proxy in %s", keycloakNamespace)

	cleanups = append(cleanups, func() {
		if err := kubeClient.NetworkingV1().NetworkPolicies(keycloakNamespace).Delete(ctx, "proxy-e2e-allow-only-from-proxy", metav1.DeleteOptions{}); err != nil {
			t.Logf("error cleaning up NetworkPolicy in %s: %v", keycloakNamespace, err)
		}
	})

	return func() {
		for _, c := range cleanups {
			c()
		}
	}
}

// GetSquidProxyLogs reads the logs from the Squid proxy pod in the given namespace.
func GetSquidProxyLogs(t testing.TB, kubeClient kubernetes.Interface, namespace string) string {
	ctx := context.TODO()

	pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", squidServiceName),
	})
	require.NoError(t, err)
	require.NotEmpty(t, pods.Items, "no squid proxy pods found in namespace %s", namespace)

	logBytes, err := kubeClient.CoreV1().Pods(namespace).GetLogs(pods.Items[0].Name, &corev1.PodLogOptions{}).DoRaw(ctx)
	require.NoError(t, err)

	return string(logBytes)
}

// WaitForSquidProxyTraffic polls the Squid proxy logs until it sees CONNECT or
// TCP_ entries, indicating traffic went through the proxy.
func WaitForSquidProxyTraffic(t testing.TB, kubeClient kubernetes.Interface, namespace string, timeout time.Duration) error {
	t.Logf("waiting up to %s for traffic in squid proxy logs", timeout)
	return wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		logs := GetSquidProxyLogs(t, kubeClient, namespace)
		if bytes.Contains([]byte(logs), []byte("CONNECT")) || bytes.Contains([]byte(logs), []byte("TCP_")) {
			t.Logf("detected proxy traffic in squid logs")
			return true, nil
		}
		return false, nil
	})
}

// GetOAuthServerProxyEnvVars reads the OAuth server deployment and returns the
// proxy-related environment variables from the container spec.
func GetOAuthServerProxyEnvVars(t testing.TB, kubeClient kubernetes.Interface) map[string]string {
	ctx := context.TODO()

	deployment, err := kubeClient.AppsV1().Deployments("openshift-authentication").Get(ctx, "oauth-openshift", metav1.GetOptions{})
	require.NoError(t, err)

	envVars := make(map[string]string)
	for _, container := range deployment.Spec.Template.Spec.Containers {
		for _, env := range container.Env {
			switch env.Name {
			case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY":
				envVars[env.Name] = env.Value
			}
		}
	}
	return envVars
}

// VerifyOAuthServerDeploymentProxyConfig asserts that the OAuth server deployment
// has the expected proxy env vars. If trustedCAConfigMap is non-empty, it also
// verifies that the corresponding volume and volume mount exist.
func VerifyOAuthServerDeploymentProxyConfig(t testing.TB, kubeClient kubernetes.Interface, expectedProxyURL, trustedCAConfigMap string) {
	ctx := context.TODO()

	deployment, err := kubeClient.AppsV1().Deployments("openshift-authentication").Get(ctx, "oauth-openshift", metav1.GetOptions{})
	require.NoError(t, err)

	envVars := GetOAuthServerProxyEnvVars(t, kubeClient)
	if expectedProxyURL != "" {
		require.Contains(t, envVars, "HTTPS_PROXY", "HTTPS_PROXY env var should be set on OAuth server")
		require.Equal(t, expectedProxyURL, envVars["HTTPS_PROXY"], "HTTPS_PROXY should match the component proxy URL")
	}

	if trustedCAConfigMap == "" {
		return
	}

	foundVolume := false
	for _, vol := range deployment.Spec.Template.Spec.Volumes {
		if vol.ConfigMap != nil && vol.ConfigMap.Name == trustedCAConfigMap {
			foundVolume = true
			break
		}
	}
	require.True(t, foundVolume, "expected volume for trustedCA ConfigMap %s", trustedCAConfigMap)

	foundMount := false
	for _, container := range deployment.Spec.Template.Spec.Containers {
		for _, mount := range container.VolumeMounts {
			if mount.Name == trustedCAConfigMap {
				foundMount = true
				break
			}
		}
	}
	require.True(t, foundMount, "expected volume mount for trustedCA ConfigMap %s", trustedCAConfigMap)
}

// VerifyTrustedCAConfigMapSynced checks that a trusted CA ConfigMap has been
// synced from openshift-config to the openshift-authentication namespace.
func VerifyTrustedCAConfigMapSynced(t testing.TB, kubeClient kubernetes.Interface, configMapName string) {
	ctx := context.TODO()

	cm, err := kubeClient.CoreV1().ConfigMaps("openshift-authentication").Get(ctx, configMapName, metav1.GetOptions{})
	require.NoError(t, err, "trustedCA ConfigMap %s should exist in openshift-authentication", configMapName)
	require.NotEmpty(t, cm.Data, "trustedCA ConfigMap %s should have data", configMapName)
}

func protocolPtr(p corev1.Protocol) *corev1.Protocol {
	return &p
}
