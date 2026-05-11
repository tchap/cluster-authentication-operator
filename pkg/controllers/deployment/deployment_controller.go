package deployment

import (
	"context"
	"fmt"
	"os"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	appsv1client "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	routeinformers "github.com/openshift/client-go/route/informers/externalversions"
	routev1listers "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/cluster-authentication-operator/bindata"
	"github.com/openshift/cluster-authentication-operator/pkg/controllers/common"
	bootstrap "github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/apiserver/controller/workload"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/openshift/library-go/pkg/route/routeapihelpers"
)

var _ workload.Delegate = &oauthServerDeploymentSyncer{}

// nodeCountFunction a function to return count of nodes
type nodeCountFunc func(nodeSelector map[string]string) (*int32, error)

// ensureAtMostOnePodPerNode a function that updates the deployment spec to prevent more than
// one pod of a given replicaset from landing on a node.
type ensureAtMostOnePodPerNodeFunc func(spec *appsv1.DeploymentSpec, componentName string) error

type oauthServerDeploymentSyncer struct {
	operatorClient v1helpers.OperatorClient

	// countNodes a function to return count of nodes on which the workload will be installed
	countNodes nodeCountFunc
	// ensureAtMostOnePodPerNode a function that updates the deployment spec to prevent more than
	// one pod of a given replicaset from landing on a node.
	ensureAtMostOnePodPerNode ensureAtMostOnePodPerNodeFunc

	deployments       appsv1client.DeploymentsGetter
	deploymentsLister appsv1listers.DeploymentLister

	configMaps     corev1client.ConfigMapsGetter
	configMapLister corev1listers.ConfigMapLister
	sourceConfigMapLister corev1listers.ConfigMapLister // openshift-config namespace
	secretLister    corev1listers.SecretLister
	podsLister      corev1listers.PodLister
	proxyLister     configv1listers.ProxyLister
	routeLister     routev1listers.RouteLister

	operatorAuthLister  operatorv1listers.AuthenticationLister
	featureGateAccessor featuregates.FeatureGateAccess

	authConfigChecker          common.AuthConfigChecker
	bootstrapUserDataGetter    bootstrap.BootstrapUserDataGetter
	bootstrapUserChangeRollOut bool
}

func NewOAuthServerWorkloadController(
	operatorClient v1helpers.OperatorClient,
	countNodes nodeCountFunc,
	ensureAtMostOnePodPerNode ensureAtMostOnePodPerNodeFunc,
	kubeClient kubernetes.Interface,
	nodeInformer coreinformers.NodeInformer,
	configInformers configinformer.SharedInformerFactory,
	routeInformersForTargetNamespace routeinformers.SharedInformerFactory,
	bootstrapUserDataGetter bootstrap.BootstrapUserDataGetter,
	eventsRecorder events.Recorder,
	versionRecorder status.VersionGetter,
	kubeInformersForTargetNamespace informers.SharedInformerFactory,
	kubeInformersForSourceNamespace informers.SharedInformerFactory,
	authConfigChecker common.AuthConfigChecker,
	operatorAuthLister operatorv1listers.AuthenticationLister,
	featureGateAccessor featuregates.FeatureGateAccess,
	operatorAuthInformer factory.Informer,
) factory.Controller {
	targetNS := "openshift-authentication"

	oauthDeploymentSyncer := &oauthServerDeploymentSyncer{
		operatorClient: operatorClient,

		countNodes:                countNodes,
		ensureAtMostOnePodPerNode: ensureAtMostOnePodPerNode,

		deployments:       kubeClient.AppsV1(),
		deploymentsLister: kubeInformersForTargetNamespace.Apps().V1().Deployments().Lister(),

		configMaps:            kubeClient.CoreV1(),
		configMapLister:       kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Lister(),
		sourceConfigMapLister: kubeInformersForSourceNamespace.Core().V1().ConfigMaps().Lister(),
		secretLister:          kubeInformersForTargetNamespace.Core().V1().Secrets().Lister(),
		podsLister:            kubeInformersForTargetNamespace.Core().V1().Pods().Lister(),
		proxyLister:           configInformers.Config().V1().Proxies().Lister(),
		routeLister:           routeInformersForTargetNamespace.Route().V1().Routes().Lister(),

		operatorAuthLister:  operatorAuthLister,
		featureGateAccessor: featureGateAccessor,

		authConfigChecker:       authConfigChecker,
		bootstrapUserDataGetter: bootstrapUserDataGetter,
	}

	if userExists, err := oauthDeploymentSyncer.bootstrapUserDataGetter.IsEnabled(); err != nil {
		klog.Warningf("unable to determine the state of bootstrap user: %v", err)
		oauthDeploymentSyncer.bootstrapUserChangeRollOut = true
	} else {
		oauthDeploymentSyncer.bootstrapUserChangeRollOut = userExists
	}

	clusterScopedInformers := []factory.Informer{
		configInformers.Config().V1().Ingresses().Informer(),
		configInformers.Config().V1().Proxies().Informer(),
		nodeInformer.Informer(),
		operatorAuthInformer,
	}
	clusterScopedInformers = append(clusterScopedInformers, common.AuthConfigCheckerInformers[factory.Informer](&authConfigChecker)...)

	return workload.NewController(
		"OAuthServer",
		"cluster-authentication-operator",
		targetNS,
		os.Getenv("OPERAND_OAUTH_SERVER_IMAGE_VERSION"),
		"",
		"OAuthServer",
		operatorClient,
		kubeClient,
		kubeInformersForTargetNamespace.Core().V1().Pods().Lister(),
		clusterScopedInformers,
		[]factory.Informer{
			kubeInformersForTargetNamespace.Apps().V1().Deployments().Informer(),
			kubeInformersForTargetNamespace.Core().V1().ConfigMaps().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Secrets().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Pods().Informer(),
			kubeInformersForTargetNamespace.Core().V1().Namespaces().Informer(),
			routeInformersForTargetNamespace.Route().V1().Routes().Informer(),
			kubeInformersForSourceNamespace.Core().V1().ConfigMaps().Informer(),
		},
		oauthDeploymentSyncer,
		eventsRecorder,
		versionRecorder,
	)
}

func (c *oauthServerDeploymentSyncer) WorkloadDeleted(ctx context.Context) (bool, string, error) {
	if oidcAvailable, err := c.authConfigChecker.OIDCAvailable(); err != nil {
		return false, "", fmt.Errorf("failed to check workload deletion: %v", err)
	} else if !oidcAvailable {
		return false, "", nil
	}

	// OIDC has been configured and rolled out; delete deployment if it exists

	deployment := resourceread.ReadDeploymentV1OrDie(bindata.MustAsset("oauth-openshift/deployment.yaml"))
	if _, err := c.deploymentsLister.Deployments(deployment.Namespace).Get(deployment.Name); errors.IsNotFound(err) {
		return true, deployment.Name, nil
	} else if err != nil {
		return false, "", fmt.Errorf("failed to retrieve deployment %s/%s for deletion: %v", deployment.Namespace, deployment.Name, err)
	}

	if err := c.deployments.Deployments(deployment.Namespace).Delete(ctx, deployment.Name, metav1.DeleteOptions{}); err != nil {
		return false, "", fmt.Errorf("could not delete deployment %s/%s: %v", deployment.Namespace, deployment.Name, err)
	}

	return true, deployment.Name, nil
}

func (c *oauthServerDeploymentSyncer) PreconditionFulfilled(_ context.Context) (bool, error) {
	if oidcAvailable, err := c.authConfigChecker.OIDCAvailable(); err != nil {
		return false, fmt.Errorf("checking if authentication mode is OIDC: %v", err)
	} else if oidcAvailable {
		// the route is no longer a pre-requisite
		return true, nil
	}

	route, err := c.routeLister.Routes("openshift-authentication").Get("oauth-openshift")
	if err != nil {
		return false, fmt.Errorf("waiting for the oauth-openshift route to appear: %w", err)
	}

	if _, _, err := routeapihelpers.IngressURI(route, ""); err != nil {
		return false, fmt.Errorf("waiting for the oauth-openshift route to contain an admitted ingress: %w", err)
	}

	return true, nil
}

func (c *oauthServerDeploymentSyncer) Sync(ctx context.Context, syncContext factory.SyncContext) (*appsv1.Deployment, bool, []error) {
	errs := []error{}

	operatorSpec, operatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return nil, false, append(errs, err)
	}

	authProxy, err := common.GetComponentProxyConfig(c.featureGateAccessor, c.operatorAuthLister)
	if err != nil {
		klog.Warningf("failed to get component proxy config, falling back to cluster-wide proxy: %v", err)
	}

	clusterProxy, err := c.getProxyConfig()
	if err != nil {
		return nil, false, append(errs, err)
	}

	httpProxy, httpsProxy, noProxy := common.ResolveProxyConfig(authProxy, clusterProxy)

	if err := c.setComponentProxyUpgradeableCondition(ctx, authProxy); err != nil {
		errs = append(errs, fmt.Errorf("setting upgradeable condition: %v", err))
	}

	// resourceVersions serves to store versions of config resources so that we
	// can redeploy our payload should either change. We only omit the operator
	// config version, it would both cause redeploy loops (status updates cause
	// version change) and the relevant changes (logLevel, unsupportedConfigOverrides)
	// will cause a redeploy anyway
	// TODO move this hash from deployment meta to operatorConfig.status.generations.[...].hash
	resourceVersions := []string{}

	resourceVersions = append(resourceVersions,
		fmt.Sprintf("proxy:%s:%s:%s", httpProxy, httpsProxy, noProxy))

	configResourceVersions, err := c.getConfigResourceVersions()
	if err != nil {
		return nil, false, append(errs, err)
	}

	resourceVersions = append(resourceVersions, configResourceVersions...)

	// Determine whether the bootstrap user has been deleted so that
	// detail can be used in computing the deployment.
	if c.bootstrapUserChangeRollOut {
		if userExists, err := c.bootstrapUserDataGetter.IsEnabled(); err != nil {
			klog.Warningf("unable to determine the state of bootstrap user: %v", err)
		} else {
			c.bootstrapUserChangeRollOut = userExists
		}
	}

	// deployment, have RV of all resources
	expectedDeployment, err := getOAuthServerDeployment(operatorSpec, httpProxy, httpsProxy, noProxy, c.bootstrapUserChangeRollOut, resourceVersions...)
	if err != nil {
		return nil, false, append(errs, err)
	}

	if _, err := c.secretLister.Secrets("openshift-authentication").Get("v4-0-config-system-custom-router-certs"); err == nil {
		expectedDeployment.Spec.Template.Spec.Volumes = append(expectedDeployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "v4-0-config-system-custom-router-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "v4-0-config-system-custom-router-certs",
				},
			},
		})
		expectedDeployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(expectedDeployment.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name:      "v4-0-config-system-custom-router-certs",
			ReadOnly:  true,
			MountPath: "/var/config/system/secrets/v4-0-config-system-custom-router-certs",
		})
	}

	if err := c.syncComponentProxyCA(ctx, syncContext, authProxy, expectedDeployment); err != nil {
		return nil, false, append(errs, fmt.Errorf("syncing component proxy CA: %v", err))
	}

	err = c.ensureAtMostOnePodPerNode(&expectedDeployment.Spec, "oauth-openshift")
	if err != nil {
		return nil, false, append(errs, fmt.Errorf("unable to ensure at most one pod per node: %v", err))
	}

	// Set the replica count to the number of control plane nodes.
	controlPlaneCount, err := c.countNodes(expectedDeployment.Spec.Template.Spec.NodeSelector)
	if err != nil {
		return nil, false, append(errs, fmt.Errorf("failed to determine number of control plane nodes: %v", err))
	}
	if controlPlaneCount == nil {
		return nil, false, append(errs, fmt.Errorf("found nil control plane nodes count"))
	}

	expectedDeployment.Spec.Replicas = controlPlaneCount
	setRollingUpdateParameters(*controlPlaneCount, expectedDeployment)

	deployment, _, err := resourceapply.ApplyDeployment(ctx, c.deployments,
		syncContext.Recorder(),
		expectedDeployment,
		resourcemerge.ExpectedDeploymentGeneration(expectedDeployment, operatorStatus.Generations),
	)
	if err != nil {
		return nil, false, append(errs, fmt.Errorf("applying deployment of the integrated OAuth server failed: %w", err))
	}

	return deployment, true, errs
}

func (c *oauthServerDeploymentSyncer) getProxyConfig() (*configv1.Proxy, error) {
	proxyConfig, err := c.proxyLister.Get("cluster")
	if err != nil {
		if errors.IsNotFound(err) {
			klog.V(4).Infof("No proxy configuration found, defaulting to empty")
			return &configv1.Proxy{}, nil
		}
		return nil, fmt.Errorf("unable to get cluster proxy configuration: %v", err)
	}
	return proxyConfig, nil
}

func (c *oauthServerDeploymentSyncer) getConfigResourceVersions() ([]string, error) {
	var configRVs []string

	configMaps, err := c.configMapLister.ConfigMaps("openshift-authentication").List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("unable to list configmaps in %q namespace: %v", "openshift-authentication", err)
	}
	for _, cm := range configMaps {
		if strings.HasPrefix(cm.Name, "v4-0-config-") {
			// prefix the RV to make it clear where it came from since each resource can be from different etcd
			configRVs = append(configRVs, "configmaps:"+cm.Name+":"+cm.ResourceVersion)
		}
	}

	secrets, err := c.secretLister.Secrets("openshift-authentication").List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("unable to list secrets in %q namespace: %v", "openshift-authentication", err)
	}
	for _, secret := range secrets {
		if strings.HasPrefix(secret.Name, "v4-0-config-") {
			// prefix the RV to make it clear where it came from since each resource can be from different etcd
			configRVs = append(configRVs, "secrets:"+secret.Name+":"+secret.ResourceVersion)
		}
	}

	return configRVs, nil
}

// Given the control plane sizes, we adjust the max unavailable and max surge values to mimic "MinAvailable".
// We always ensure it is controlPlaneCount - 1, as this allows us to keep have at least a single replica running.
// We also set MaxSurge to always be exactly the control plane count, as this allows us to more quickly replace failing
// deployments with a new replica set. This does not clash with the pod anti affinity set above.
func setRollingUpdateParameters(controlPlaneCount int32, deployment *appsv1.Deployment) {
	maxUnavailable := intstr.FromInt32(max(controlPlaneCount-1, 1))
	maxSurge := intstr.FromInt32(controlPlaneCount)
	deployment.Spec.Strategy.RollingUpdate.MaxUnavailable = &maxUnavailable
	deployment.Spec.Strategy.RollingUpdate.MaxSurge = &maxSurge
}

const (
	componentProxyUpgradeableCondition = "AuthenticationComponentProxyUpgradeable"
	componentProxyCAConfigMapName      = "v4-0-config-system-auth-proxy-ca"
	componentProxyCAMountPath     = "/var/config/system/configmaps/" + componentProxyCAConfigMapName
)

func (c *oauthServerDeploymentSyncer) setComponentProxyUpgradeableCondition(
	ctx context.Context,
	authProxy *operatorv1.AuthenticationProxyConfig,
) error {
	if authProxy == nil {
		return nil
	}

	cond := applyoperatorv1.OperatorCondition().
		WithType(componentProxyUpgradeableCondition).
		WithStatus(operatorv1.ConditionFalse).
		WithReason("ComponentProxyConfigured").
		WithMessage("component-scoped proxy is configured; upgrades are blocked while this TechPreview feature is in use")

	return c.operatorClient.ApplyOperatorStatus(
		ctx,
		"OAuthServerDeployment",
		applyoperatorv1.OperatorStatus().WithConditions(cond),
	)
}

// syncComponentProxyCA copies the component-scoped proxy CA ConfigMap from
// openshift-config to openshift-authentication and adds volume/mount + entrypoint
// append to the OAuth Server deployment so the CA is included in system trust.
func (c *oauthServerDeploymentSyncer) syncComponentProxyCA(
	ctx context.Context,
	syncContext factory.SyncContext,
	authProxy *operatorv1.AuthenticationProxyConfig,
	deployment *appsv1.Deployment,
) error {
	if authProxy == nil || len(authProxy.TrustedCA.Name) == 0 {
		return nil
	}

	sourceCM, err := c.sourceConfigMapLister.ConfigMaps("openshift-config").Get(authProxy.TrustedCA.Name)
	if err != nil {
		return fmt.Errorf("getting component proxy CA configmap %s/%s: %v", "openshift-config", authProxy.TrustedCA.Name, err)
	}

	targetCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "openshift-authentication",
			Name:      componentProxyCAConfigMapName,
		},
		Data: sourceCM.Data,
	}
	_, _, err = resourceapply.ApplyConfigMap(ctx, c.configMaps, syncContext.Recorder(), targetCM)
	if err != nil {
		return fmt.Errorf("applying component proxy CA configmap to openshift-authentication: %v", err)
	}

	operatorTargetCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "openshift-authentication-operator",
			Name:      "auth-proxy-ca",
		},
		Data: sourceCM.Data,
	}
	_, _, err = resourceapply.ApplyConfigMap(ctx, c.configMaps, syncContext.Recorder(), operatorTargetCM)
	if err != nil {
		return fmt.Errorf("applying component proxy CA configmap to openshift-authentication-operator: %v", err)
	}

	deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
		Name: componentProxyCAConfigMapName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: componentProxyCAConfigMapName,
				},
				Optional: ptr.To(true),
			},
		},
	})
	deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts,
		corev1.VolumeMount{
			Name:      componentProxyCAConfigMapName,
			ReadOnly:  true,
			MountPath: componentProxyCAMountPath,
		},
	)

	// Inject entrypoint append to add component proxy CA to system trust.
	// The existing entrypoint copies system trust then runs the server;
	// insert the append block before the exec line.
	appendBlock := fmt.Sprintf(
		"\nif [ -s %s/ca-bundle.crt ]; then\n"+
			"    echo \"Appending component proxy CA bundle\"\n"+
			"    cat %s/ca-bundle.crt >> /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem\n"+
			"fi\n",
		componentProxyCAMountPath, componentProxyCAMountPath,
	)
	deployment.Spec.Template.Spec.Containers[0].Args[0] = strings.Replace(
		deployment.Spec.Template.Spec.Containers[0].Args[0],
		"exec oauth-server",
		appendBlock+"exec oauth-server",
		1,
	)

	return nil
}
