// Package rds provides functionality to enumerate and integrate AWS RDS resources.
package rds

import (
	// Standard
	"context"
	// Generated
	rdsfern "github.com/Method-Security/methodaws/generated/go/rds"
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func EnumerateRDS(ctx context.Context, awsConfig aws.Config, config rdsfern.RdsEnumerateConfig) *rdsfern.RdsEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting RDS enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &rdsfern.RdsEnumerateReport{
		Config: &config,
		Result: &rdsfern.RdsEnumerateResult{},
	}

	var allRDSInstances []*rdsfern.RdsInstance
	var allErrors []string

	for _, region := range config.Regions {
		log.Info("Processing RDS instances in region", svc1log.SafeParam("region", region))
		instances, errors := enumerateRDSForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating RDS instances in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allRDSInstances = append(allRDSInstances, instances...)
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed RDS instances in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("instanceCount", len(instances)))
	}

	// Marshal report
	if len(allRDSInstances) > 0 {
		report.Result.RdsInstances = allRDSInstances
	}

	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed RDS enumeration",
		svc1log.SafeParam("totalInstances", len(allRDSInstances)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

func enumerateRDSForRegion(ctx context.Context, awsConfig aws.Config, region string) ([]*rdsfern.RdsInstance, []string) {
	log := svc1log.FromContext(ctx)
	awsConfig.Region = region

	rdsClient := rds.NewFromConfig(awsConfig)
	var errors []string

	// List RDS instances
	instances, err := listRDSInstances(ctx, rdsClient)
	if err != nil {
		errorMsg := "Failed to list RDS instances: " + err.Error()
		log.Error("Error listing RDS instances", svc1log.SafeParam("error", err.Error()))
		errors = append(errors, errorMsg)
		return nil, errors
	}

	log.Info("Successfully listed RDS instances", svc1log.SafeParam("count", len(instances)))

	var rdsInstances []*rdsfern.RdsInstance
	for _, instance := range instances {
		rdsInstance := transformDBInstanceToFern(instance, region)
		rdsInstances = append(rdsInstances, rdsInstance)
	}

	return rdsInstances, errors
}

func listRDSInstances(ctx context.Context, rdsClient *rds.Client) ([]types.DBInstance, error) {
	var instances []types.DBInstance
	paginator := rds.NewDescribeDBInstancesPaginator(rdsClient, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		instances = append(instances, page.DBInstances...)
	}

	return instances, nil
}

func transformDBInstanceToFern(instance types.DBInstance, region string) *rdsfern.RdsInstance {
	dbInstance := &rdsfern.DbInstance{}

	// Map basic string fields
	dbInstance.DbInstanceIdentifier = instance.DBInstanceIdentifier
	dbInstance.DbInstanceClass = instance.DBInstanceClass
	dbInstance.Engine = instance.Engine
	dbInstance.EngineVersion = instance.EngineVersion
	dbInstance.DbInstanceStatus = instance.DBInstanceStatus
	dbInstance.MasterUsername = instance.MasterUsername
	dbInstance.DbName = instance.DBName
	dbInstance.AvailabilityZone = instance.AvailabilityZone
	dbInstance.DbInstanceArn = instance.DBInstanceArn
	dbInstance.DbiResourceId = instance.DbiResourceId

	// Additional basic string fields
	dbInstance.ActivityStreamKinesisStreamName = instance.ActivityStreamKinesisStreamName
	dbInstance.ActivityStreamKmsKeyId = instance.ActivityStreamKmsKeyId
	dbInstance.AwsBackupRecoveryPointArn = instance.AwsBackupRecoveryPointArn
	dbInstance.BackupTarget = instance.BackupTarget
	dbInstance.CaCertificateIdentifier = instance.CACertificateIdentifier
	dbInstance.CharacterSetName = instance.CharacterSetName
	dbInstance.CustomIamInstanceProfile = instance.CustomIamInstanceProfile
	dbInstance.DbClusterIdentifier = instance.DBClusterIdentifier
	dbInstance.DbSystemId = instance.DBSystemId
	dbInstance.EngineLifecycleSupport = instance.EngineLifecycleSupport
	dbInstance.EnhancedMonitoringResourceArn = instance.EnhancedMonitoringResourceArn
	dbInstance.KmsKeyId = instance.KmsKeyId
	dbInstance.LicenseModel = instance.LicenseModel
	dbInstance.MonitoringRoleArn = instance.MonitoringRoleArn
	dbInstance.NcharCharacterSetName = instance.NcharCharacterSetName
	dbInstance.NetworkType = instance.NetworkType
	dbInstance.PercentProgress = instance.PercentProgress
	dbInstance.PerformanceInsightsKmsKeyId = instance.PerformanceInsightsKMSKeyId
	dbInstance.PreferredBackupWindow = instance.PreferredBackupWindow
	dbInstance.PreferredMaintenanceWindow = instance.PreferredMaintenanceWindow
	dbInstance.ReadReplicaSourceDbClusterIdentifier = instance.ReadReplicaSourceDBClusterIdentifier
	dbInstance.ReadReplicaSourceDbInstanceIdentifier = instance.ReadReplicaSourceDBInstanceIdentifier
	dbInstance.SecondaryAvailabilityZone = instance.SecondaryAvailabilityZone
	dbInstance.StorageType = instance.StorageType
	dbInstance.TdeCredentialArn = instance.TdeCredentialArn
	dbInstance.Timezone = instance.Timezone

	// Map integer fields
	if instance.AllocatedStorage != nil {
		allocatedStorage := int(*instance.AllocatedStorage)
		dbInstance.AllocatedStorage = &allocatedStorage
	}
	if instance.DbInstancePort != nil {
		dbInstancePort := int(*instance.DbInstancePort)
		dbInstance.DbInstancePort = &dbInstancePort
	}
	if instance.Iops != nil {
		iops := int(*instance.Iops)
		dbInstance.Iops = &iops
	}
	if instance.BackupRetentionPeriod != nil {
		backupRetention := int(*instance.BackupRetentionPeriod)
		dbInstance.BackupRetentionPeriod = &backupRetention
	}
	if instance.MaxAllocatedStorage != nil {
		maxStorage := int(*instance.MaxAllocatedStorage)
		dbInstance.MaxAllocatedStorage = &maxStorage
	}
	if instance.MonitoringInterval != nil {
		monitoringInterval := int(*instance.MonitoringInterval)
		dbInstance.MonitoringInterval = &monitoringInterval
	}
	if instance.PerformanceInsightsRetentionPeriod != nil {
		retentionPeriod := int(*instance.PerformanceInsightsRetentionPeriod)
		dbInstance.PerformanceInsightsRetentionPeriod = &retentionPeriod
	}
	if instance.PromotionTier != nil {
		promotionTier := int(*instance.PromotionTier)
		dbInstance.PromotionTier = &promotionTier
	}
	if instance.StorageThroughput != nil {
		storageThroughput := int(*instance.StorageThroughput)
		dbInstance.StorageThroughput = &storageThroughput
	}

	// Map boolean fields
	dbInstance.MultiAz = instance.MultiAZ
	dbInstance.PubliclyAccessible = instance.PubliclyAccessible
	dbInstance.StorageEncrypted = instance.StorageEncrypted
	dbInstance.AutoMinorVersionUpgrade = instance.AutoMinorVersionUpgrade
	dbInstance.ActivityStreamEngineNativeAuditFieldsIncluded = instance.ActivityStreamEngineNativeAuditFieldsIncluded
	dbInstance.CopyTagsToSnapshot = instance.CopyTagsToSnapshot
	dbInstance.CustomerOwnedIpEnabled = instance.CustomerOwnedIpEnabled
	dbInstance.DedicatedLogVolume = instance.DedicatedLogVolume
	dbInstance.DeletionProtection = instance.DeletionProtection
	dbInstance.IamDatabaseAuthenticationEnabled = instance.IAMDatabaseAuthenticationEnabled
	dbInstance.IsStorageConfigUpgradeAvailable = instance.IsStorageConfigUpgradeAvailable
	dbInstance.MultiTenant = instance.MultiTenant
	dbInstance.PerformanceInsightsEnabled = instance.PerformanceInsightsEnabled

	// Map enum fields
	if instance.ActivityStreamMode != "" {
		activityStreamMode := rdsfern.ActivityStreamMode(instance.ActivityStreamMode)
		dbInstance.ActivityStreamMode = &activityStreamMode
	}
	if instance.ActivityStreamStatus != "" {
		activityStreamStatus := rdsfern.ActivityStreamStatus(instance.ActivityStreamStatus)
		dbInstance.ActivityStreamStatus = &activityStreamStatus
	}
	if instance.AutomationMode != "" {
		automationMode := rdsfern.AutomationMode(instance.AutomationMode)
		dbInstance.AutomationMode = &automationMode
	}
	if instance.DatabaseInsightsMode != "" {
		databaseInsightsMode := rdsfern.DatabaseInsightsMode(instance.DatabaseInsightsMode)
		dbInstance.DatabaseInsightsMode = &databaseInsightsMode
	}
	if instance.ReplicaMode != "" {
		replicaMode := rdsfern.ReplicaMode(instance.ReplicaMode)
		dbInstance.ReplicaMode = &replicaMode
	}

	// Map time fields
	if instance.AutomaticRestartTime != nil {
		automaticRestartTime := instance.AutomaticRestartTime.Format("2006-01-02T15:04:05Z07:00")
		dbInstance.AutomaticRestartTime = &automaticRestartTime
	}
	if instance.InstanceCreateTime != nil {
		instanceCreateTime := instance.InstanceCreateTime.Format("2006-01-02T15:04:05Z07:00")
		dbInstance.InstanceCreateTime = &instanceCreateTime
	}
	if instance.LatestRestorableTime != nil {
		latestRestorableTime := instance.LatestRestorableTime.Format("2006-01-02T15:04:05Z07:00")
		dbInstance.LatestRestorableTime = &latestRestorableTime
	}
	if instance.ResumeFullAutomationModeTime != nil {
		resumeTime := instance.ResumeFullAutomationModeTime.Format("2006-01-02T15:04:05Z07:00")
		dbInstance.ResumeFullAutomationModeTime = &resumeTime
	}

	// Map string arrays
	dbInstance.EnabledCloudwatchLogsExports = instance.EnabledCloudwatchLogsExports
	dbInstance.ReadReplicaDbClusterIdentifiers = instance.ReadReplicaDBClusterIdentifiers
	dbInstance.ReadReplicaDbInstanceIdentifiers = instance.ReadReplicaDBInstanceIdentifiers

	// Map endpoint
	if instance.Endpoint != nil {
		endpoint := &rdsfern.Endpoint{}
		if instance.Endpoint.Address != nil {
			endpoint.Address = instance.Endpoint.Address
		}
		if instance.Endpoint.Port != nil {
			port := int(*instance.Endpoint.Port)
			endpoint.Port = &port
		}
		if instance.Endpoint.HostedZoneId != nil {
			endpoint.HostedZoneId = instance.Endpoint.HostedZoneId
		}
		dbInstance.Endpoint = endpoint
	}

	// Map listener endpoint
	if instance.ListenerEndpoint != nil {
		listenerEndpoint := &rdsfern.Endpoint{}
		if instance.ListenerEndpoint.Address != nil {
			listenerEndpoint.Address = instance.ListenerEndpoint.Address
		}
		if instance.ListenerEndpoint.Port != nil {
			port := int(*instance.ListenerEndpoint.Port)
			listenerEndpoint.Port = &port
		}
		if instance.ListenerEndpoint.HostedZoneId != nil {
			listenerEndpoint.HostedZoneId = instance.ListenerEndpoint.HostedZoneId
		}
		dbInstance.ListenerEndpoint = listenerEndpoint
	}

	// Map DB subnet group
	if instance.DBSubnetGroup != nil {
		dbSubnetGroup := &rdsfern.DbSubnetGroup{
			DbSubnetGroupName:        instance.DBSubnetGroup.DBSubnetGroupName,
			DbSubnetGroupDescription: instance.DBSubnetGroup.DBSubnetGroupDescription,
			VpcId:                    instance.DBSubnetGroup.VpcId,
			SubnetGroupStatus:        instance.DBSubnetGroup.SubnetGroupStatus,
		}
		dbInstance.DbSubnetGroup = dbSubnetGroup
	}

	// Map certificate details
	if instance.CertificateDetails != nil {
		certDetails := &rdsfern.CertificateDetails{
			CaIdentifier: instance.CertificateDetails.CAIdentifier,
		}
		if instance.CertificateDetails.ValidTill != nil {
			validTill := instance.CertificateDetails.ValidTill.Format("2006-01-02T15:04:05Z07:00")
			certDetails.ValidTill = &validTill
		}
		dbInstance.CertificateDetails = certDetails
	}

	// Map master user secret
	if instance.MasterUserSecret != nil {
		masterUserSecret := &rdsfern.MasterUserSecret{
			SecretArn:    instance.MasterUserSecret.SecretArn,
			SecretStatus: instance.MasterUserSecret.SecretStatus,
			KmsKeyId:     instance.MasterUserSecret.KmsKeyId,
		}
		dbInstance.MasterUserSecret = masterUserSecret
	}

	// Map associated roles
	if len(instance.AssociatedRoles) > 0 {
		var associatedRoles []*rdsfern.DbInstanceRole
		for _, role := range instance.AssociatedRoles {
			fernRole := &rdsfern.DbInstanceRole{
				RoleArn:     role.RoleArn,
				FeatureName: role.FeatureName,
				Status:      role.Status,
			}
			associatedRoles = append(associatedRoles, fernRole)
		}
		dbInstance.AssociatedRoles = associatedRoles
	}

	// Map VPC security groups
	if len(instance.VpcSecurityGroups) > 0 {
		var vpcSecurityGroups []*rdsfern.VpcSecurityGroupMembership
		for _, sg := range instance.VpcSecurityGroups {
			fernSg := &rdsfern.VpcSecurityGroupMembership{
				VpcSecurityGroupId: sg.VpcSecurityGroupId,
				Status:             sg.Status,
			}
			vpcSecurityGroups = append(vpcSecurityGroups, fernSg)
		}
		dbInstance.VpcSecurityGroups = vpcSecurityGroups
	}

	// Map DB parameter groups
	if len(instance.DBParameterGroups) > 0 {
		var dbParameterGroups []*rdsfern.DbParameterGroupStatus
		for _, pg := range instance.DBParameterGroups {
			fernPg := &rdsfern.DbParameterGroupStatus{
				DbParameterGroupName: pg.DBParameterGroupName,
				ParameterApplyStatus: pg.ParameterApplyStatus,
			}
			dbParameterGroups = append(dbParameterGroups, fernPg)
		}
		dbInstance.DbParameterGroups = dbParameterGroups
	}

	// Map DB security groups
	if len(instance.DBSecurityGroups) > 0 {
		var dbSecurityGroups []*rdsfern.DbSecurityGroupMembership
		for _, sg := range instance.DBSecurityGroups {
			fernSg := &rdsfern.DbSecurityGroupMembership{
				DbSecurityGroupName: sg.DBSecurityGroupName,
				Status:              sg.Status,
			}
			dbSecurityGroups = append(dbSecurityGroups, fernSg)
		}
		dbInstance.DbSecurityGroups = dbSecurityGroups
	}

	// Map option group memberships
	if len(instance.OptionGroupMemberships) > 0 {
		var optionGroups []*rdsfern.OptionGroupMembership
		for _, og := range instance.OptionGroupMemberships {
			fernOg := &rdsfern.OptionGroupMembership{
				OptionGroupName: og.OptionGroupName,
				Status:          og.Status,
			}
			optionGroups = append(optionGroups, fernOg)
		}
		dbInstance.OptionGroupMemberships = optionGroups
	}

	// Map processor features
	if len(instance.ProcessorFeatures) > 0 {
		var processorFeatures []*rdsfern.ProcessorFeature
		for _, pf := range instance.ProcessorFeatures {
			fernPf := &rdsfern.ProcessorFeature{
				Name:  pf.Name,
				Value: pf.Value,
			}
			processorFeatures = append(processorFeatures, fernPf)
		}
		dbInstance.ProcessorFeatures = processorFeatures
	}

	// Map domain memberships
	if len(instance.DomainMemberships) > 0 {
		var domainMemberships []*rdsfern.DomainMembership
		for _, dm := range instance.DomainMemberships {
			fernDm := &rdsfern.DomainMembership{
				Domain:              dm.Domain,
				Status:              dm.Status,
				Fqdn:                dm.FQDN,
				IamRoleName:         dm.IAMRoleName,
				OudistinguishedName: dm.OU,
			}
			domainMemberships = append(domainMemberships, fernDm)
		}
		dbInstance.DomainMemberships = domainMemberships
	}

	// Map status infos
	if len(instance.StatusInfos) > 0 {
		var statusInfos []*rdsfern.DbInstanceStatusInfo
		for _, si := range instance.StatusInfos {
			fernSi := &rdsfern.DbInstanceStatusInfo{
				StatusType: si.StatusType,
				Normal:     si.Normal,
				Status:     si.Status,
				Message:    si.Message,
			}
			statusInfos = append(statusInfos, fernSi)
		}
		dbInstance.StatusInfos = statusInfos
	}

	// Map DB instance automated backups replications
	if len(instance.DBInstanceAutomatedBackupsReplications) > 0 {
		var automatedBackupsReplications []*rdsfern.DbInstanceAutomatedBackupsReplication
		for _, abr := range instance.DBInstanceAutomatedBackupsReplications {
			fernAbr := &rdsfern.DbInstanceAutomatedBackupsReplication{
				Arn: abr.DBInstanceAutomatedBackupsArn,
			}
			automatedBackupsReplications = append(automatedBackupsReplications, fernAbr)
		}
		dbInstance.DbInstanceAutomatedBackupsReplications = automatedBackupsReplications
	}

	// Map pending modified values
	if instance.PendingModifiedValues != nil {
		pmv := &rdsfern.PendingModifiedValues{
			DbInstanceClass:         instance.PendingModifiedValues.DBInstanceClass,
			MasterUserPassword:      instance.PendingModifiedValues.MasterUserPassword,
			EngineVersion:           instance.PendingModifiedValues.EngineVersion,
			LicenseModel:            instance.PendingModifiedValues.LicenseModel,
			DbInstanceIdentifier:    instance.PendingModifiedValues.DBInstanceIdentifier,
			StorageType:             instance.PendingModifiedValues.StorageType,
			CaCertificateIdentifier: instance.PendingModifiedValues.CACertificateIdentifier,
			DbSubnetGroupName:       instance.PendingModifiedValues.DBSubnetGroupName,
			MultiAz:                 instance.PendingModifiedValues.MultiAZ,
			DedicatedLogVolume:      instance.PendingModifiedValues.DedicatedLogVolume,
		}
		if instance.PendingModifiedValues.AllocatedStorage != nil {
			allocatedStorage := int(*instance.PendingModifiedValues.AllocatedStorage)
			pmv.AllocatedStorage = &allocatedStorage
		}
		if instance.PendingModifiedValues.Port != nil {
			port := int(*instance.PendingModifiedValues.Port)
			pmv.Port = &port
		}
		if instance.PendingModifiedValues.BackupRetentionPeriod != nil {
			backupRetention := int(*instance.PendingModifiedValues.BackupRetentionPeriod)
			pmv.BackupRetentionPeriod = &backupRetention
		}
		if instance.PendingModifiedValues.Iops != nil {
			iops := int(*instance.PendingModifiedValues.Iops)
			pmv.Iops = &iops
		}
		if instance.PendingModifiedValues.StorageThroughput != nil {
			storageThroughput := int(*instance.PendingModifiedValues.StorageThroughput)
			pmv.StorageThroughput = &storageThroughput
		}
		dbInstance.PendingModifiedValues = pmv
	}

	// Map tags
	if len(instance.TagList) > 0 {
		var tags []*rdsfern.Tag
		for _, tag := range instance.TagList {
			fernTag := &rdsfern.Tag{}
			fernTag.Key = tag.Key
			fernTag.Value = tag.Value
			tags = append(tags, fernTag)
		}
		dbInstance.TagList = tags
	}

	return &rdsfern.RdsInstance{
		DbInstance: dbInstance,
		Region:     region,
	}
}
