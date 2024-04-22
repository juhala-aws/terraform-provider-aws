// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudfront

// Exports for use in tests only.
var (
	ResourceCachePolicy                 = resourceCachePolicy
	ResourceContinuousDeploymentPolicy  = newContinuousDeploymentPolicyResource
	ResourceFieldLevelEncryptionConfig  = resourceFieldLevelEncryptionConfig
	ResourceFieldLevelEncryptionProfile = resourceFieldLevelEncryptionProfile
	ResourceFunction                    = resourceFunction
	ResourceKeyGroup                    = resourceKeyGroup
	ResourceKeyValueStore               = newKeyValueStoreResource
	ResourceMonitoringSubscription      = resourceMonitoringSubscription
	ResourceOriginAccessControl         = resourceOriginAccessControl
	ResourceOriginAccessIdentity        = resourceOriginAccessIdentity
	ResourceOriginRequestPolicy         = resourceOriginRequestPolicy
	ResourcePublicKey                   = resourcePublicKey
	ResourceRealtimeLogConfig           = resourceRealtimeLogConfig
	ResourceResponseHeadersPolicy       = resourceResponseHeadersPolicy

	FindCachePolicyByID                        = findCachePolicyByID
	FindFieldLevelEncryptionConfigByID         = findFieldLevelEncryptionConfigByID
	FindFieldLevelEncryptionProfileByID        = findFieldLevelEncryptionProfileByID
	FindFunctionByTwoPartKey                   = findFunctionByTwoPartKey
	FindKeyGroupByID                           = findKeyGroupByID
	FindKeyValueStoreByName                    = findKeyValueStoreByName
	FindMonitoringSubscriptionByDistributionID = findMonitoringSubscriptionByDistributionID
	FindOriginAccessControlByID                = findOriginAccessControlByID
	FindOriginAccessIdentityByID               = findOriginAccessIdentityByID
	FindOriginRequestPolicyByID                = findOriginRequestPolicyByID
	FindPublicKeyByID                          = findPublicKeyByID
	FindRealtimeLogConfigByARN                 = findRealtimeLogConfigByARN
	FindResponseHeadersPolicyByID              = findResponseHeadersPolicyByID
)
