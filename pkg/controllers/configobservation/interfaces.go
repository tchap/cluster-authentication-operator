package configobservation

import (
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

var _ configobserver.Listers = Listers{}

const (
	OAuthServerConfigPrefix = "oauthServer"
)

type Listers struct {
	SecretsLister   corelistersv1.SecretLister
	ConfigMapLister corelistersv1.ConfigMapLister

	APIServerLister_     configlistersv1.APIServerLister
	ConsoleLister        configlistersv1.ConsoleLister
	ClusterVersionLister configlistersv1.ClusterVersionLister
	InfrastructureLister configlistersv1.InfrastructureLister
	OAuthLister_         configlistersv1.OAuthLister
	IngressLister        configlistersv1.IngressLister

	OperatorAuthLister          operatorv1listers.AuthenticationLister
	FeatureGateAccessor         featuregates.FeatureGateAccess
	OperatorNamespaceConfigMaps corelistersv1.ConfigMapLister

	ResourceSync       resourcesynccontroller.ResourceSyncer
	PreRunCachesSynced []cache.InformerSynced
}

func (l Listers) APIServerLister() configlistersv1.APIServerLister {
	return l.APIServerLister_
}

func (l Listers) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return l.ResourceSync
}

func (l Listers) OAuthLister() configlistersv1.OAuthLister {
	return l.OAuthLister_
}

func (l Listers) PreRunHasSynced() []cache.InformerSynced {
	return l.PreRunCachesSynced
}
