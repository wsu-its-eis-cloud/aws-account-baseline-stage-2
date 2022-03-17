param(
	[Alias("na")]
    [switch] $networkAclSshRdp = $false,
	
	[Alias("ci")]
    [string] $customerNetworkSshRdpAllow = "", #Never set
	
	[Alias("cs")]
    [switch] $createServiceControlPolicy = $false,
	
	[Alias("d")]
    [switch] $deleteLegacy = $false, #never set this to true
	
	[Alias("sh")]
    [switch] $acceptSecurityHubInvitation = $false,
	
	[Alias("hi")]
    [string] $securityHubAccountId = "", #Never set
	
	[Alias("m")]
    [switch] $enableMacie = $false,
	
    [Alias("k")]
    [switch] $rotateKmsKeys = $false,
	
	[Alias("l")]
    [switch] $bucketLogging = $false,
	
	[Alias("b")]
    [switch] $encryptBuckets = $false,
	
	[Alias("pa")]
    [switch] $publicAccountAccessBlock = $false,
	
	[Alias("pb")]
    [switch] $publicBucketAccessBlock = $false,
	
	[Alias("s")]
    [switch] $s3SecureTransport = $false,
	
	[Alias("a")]
    [switch] $allFixes = $false,
	
	[Alias("t")]
    [switch] $transcribe = $false,
	
    [Alias("h")]
    [switch] $help = $false
)

$accountId = aws sts get-caller-identity
$accountId = ConvertFrom-Json($accountId -join "")
$accountId = $accountId.Account

$alias = aws iam list-account-aliases
$alias = ConvertFrom-Json($alias -join "")
$alias = $alias.AccountAliases[0]

# If the alias doesn't exist, the baseline hasn't been applied.
if ($alias.Length -eq 0) {
	Write-Host("Account needs the baseline applied.")
	exit
}

if ($networkAclSshRdp -or $allFixes) {
	$networkAcls = aws ec2 describe-network-acls
	$networkAcls = ConvertFrom-Json($networkAcls -join "")
	$networkAcls = $networkAcls.NetworkAcls
	
	$networkAcls | Foreach-Object {
		aws ec2 create-network-acl-entry --network-acl-id $_.NetworkAclId --ingress --rule-number 10 --protocol tcp --port-range From=22,To=22 --cidr-block 10.0.0.0/8 --rule-action allow
		aws ec2 create-network-acl-entry --network-acl-id $_.NetworkAclId --ingress --rule-number 11 --protocol tcp --port-range From=22,To=22 --cidr-block 172.16.0.0/12 --rule-action allow
		
		aws ec2 create-network-acl-entry --network-acl-id $_.NetworkAclId --ingress --rule-number 13 --protocol tcp --port-range From=3389,To=3389 --cidr-block 10.0.0.0/8 --rule-action allow
		aws ec2 create-network-acl-entry --network-acl-id $_.NetworkAclId --ingress --rule-number 14 --protocol tcp --port-range From=3389,To=3389 --cidr-block 172.16.0.0/12 --rule-action allow
		
		aws ec2 create-network-acl-entry --network-acl-id $_.NetworkAclId --ingress --rule-number 20 --protocol tcp --port-range From=22,To=22 --cidr-block 0.0.0.0/0 --rule-action deny
		aws ec2 create-network-acl-entry --network-acl-id $_.NetworkAclId --ingress --rule-number 21 --protocol tcp --port-range From=3389,To=3389 --cidr-block 0.0.0.0/0 --rule-action deny
		
		if($customerNetworkSshRdpAllow.Length -ne 0) {
			aws ec2 create-network-acl-entry --network-acl-id $_.NetworkAclId --ingress --rule-number 12 --protocol tcp --port-range From=22,To=22 --cidr-block $customerNetworkSshRdpAllow --rule-action allow
			aws ec2 create-network-acl-entry --network-acl-id $_.NetworkAclId --ingress --rule-number 15 --protocol tcp --port-range From=3389,To=3389 --cidr-block $customerNetworkSshRdpAllow --rule-action allow
		}
	}
	Write-Host("Processed all network acls.")
	
	if($allFixes -eq $false) {
		exit
	}
}

if ($createServiceControlPolicy -or $allFixes) {
	
	$policies = aws organizations list-policies --filter SERVICE_CONTROL_POLICY
	$policies = ConvertFrom-Json($policies -join "")
	$policies = $policies.Policies
	
	$denyCreateVpc = $true
	$denyMacieClassificationJob = $true
	$denyRoot = $true
	$readOnly = $true
	
	$policies | Foreach-Object {
		if ($_.Name -eq "DenyCreateVpc") {
			$denyCreateVpc = $false
		} elseif ($_.Name -eq "DenyMacieClassificationJob") {
			$denyMacieClassificationJob = $false
		} elseif ($_.Name -eq "DenyRoot") {
			$denyRoot = $false
		} elseif ($_.Name -eq "ReadOnlyAll") {
			$readOnly = $false
		}
	}
	
	$rootId = aws organizations list-roots
	$rootId = ConvertFrom-Json($rootId -join "")
	$rootId = $rootId.Roots
	$rootId = $rootId[0].Id
	
	$managedId = aws organizations list-organizational-units-for-parent --parent-id $rootId
	$managedId = ConvertFrom-Json($managedId -join "")
	$managedId = $managedId.OrganizationalUnits
	if($managedId.Count -ne 1) {
		Write-Host("Missing Managed organizational unit.")
		exit
	} elseif ($managedId[0].Name -ne "Managed") {
		Write-Host("Unexpected under root organizational unit.")
		exit
	} else {
		$managedId = $managedId[0].Id
	}

	$managedOus = aws organizations list-organizational-units-for-parent --parent-id $managedId
	$managedOus = ConvertFrom-Json($managedOus -join "")
	$managedOus = $managedOus.OrganizationalUnits
	
	$isolatedOu = ""
	$sharedOu = ""
	$retiredOu = ""
	
	$managedOus | Foreach-Object {
		if ($_.Name -eq "Isolated Networks") {
			$isolatedOu = $_.Id
		} elseif ($_.Name -eq "Shared Networks") {
			$sharedOu = $_.Id
		} elseif ($_.Name -eq "Retired") {
			$retiredOu = $_.Id
		}
	}
	
	if ($denyCreateVpc) {
		$denyCreateVpcFile = Get-Childitem -filter "deny-create-vpc.json"
		$denyCreateVpcPolicy = Get-Content $denyCreateVpcFile.FullName -raw
		$denyCreateVpcPolicy = $denyCreateVpcPolicy.Replace('"', '\"')
		
		$policy = aws organizations create-policy --content $denyCreateVpcPolicy --name "DenyCreateVpc" --type SERVICE_CONTROL_POLICY --description "Denies VPC creation for the shared networks OU to prevent briding between the WSU corp net and unmanaged networks."
		$policy = ConvertFrom-Json($policy -join "")
		$policy = $policy.Policy
		$policy = $policy.PolicySummary
		Start-Sleep 1
		
		if ($sharedOu.Length -ne 0) {
			$result = aws organizations attach-policy --policy-id $policy.Id --target-id $sharedOu
		}
	}
	
	if ($denyMacieClassificationJob) {
		$denyMacieClassificationJobFile = Get-Childitem -filter "deny-macie-classification-job.json"
		$denyMacieClassificationJobPolicy = Get-Content $denyMacieClassificationJobFile.FullName -raw
		$denyMacieClassificationJobPolicy = $denyMacieClassificationJobPolicy.Replace('"', '\"')
		
		$policy = aws organizations create-policy --content $denyMacieClassificationJobPolicy --name "DenyMacieClassificationJob" --type SERVICE_CONTROL_POLICY --description "Denies the creation of Macie classification jobs on the Managed OU to prevent unexpected costs. Allows bucket inventorying."
		$policy = ConvertFrom-Json($policy -join "")
		$policy = $policy.Policy
		$policy = $policy.PolicySummary
		Start-Sleep 1
		
		if ($managedId.Length -ne 0) {
			$result = aws organizations attach-policy --policy-id $policy.Id --target-id $managedId
		}
	}
	
	if ($denyRoot) {
		$denyRootFile = Get-Childitem -filter "deny-root.json"
		$denyRootPolicy = Get-Content $denyRootFile.FullName -raw
		$denyRootPolicy = $denyRootPolicy.Replace('"', '\"')
		
		$policy = aws organizations create-policy --content $denyRootPolicy --name "DenyRoot" --type SERVICE_CONTROL_POLICY --description "Denies root permissions to all resources as a compensating control for using virtual MFA instead of physical MFA on accounts in the Managed OU."
		$policy = ConvertFrom-Json($policy -join "")
		$policy = $policy.Policy
		$policy = $policy.PolicySummary
		Start-Sleep 1
		
		if ($managedId.Length -ne 0) {
			$result = aws organizations attach-policy --policy-id $policy.Id --target-id $managedId
		}
	}
	
	if ($readOnly) {
		$readOnlyAllFile = Get-Childitem -filter "read-only-all.json"
		$readOnlyAllPolicy = Get-Content $readOnlyAllFile.FullName -raw
		$readOnlyAllPolicy = $readOnlyAllPolicy.Replace('"', '\"')
		
		$policy = aws organizations create-policy --content $readOnlyAllPolicy --name "ReadOnlyAll" --type SERVICE_CONTROL_POLICY --description "Makes all resources in the account read only for the Retired OU."
		$policy = ConvertFrom-Json($policy -join "")
		$policy = $policy.Policy
		$policy = $policy.PolicySummary
		Start-Sleep 1
		
		if ($retiredOu.Length -ne 0) {
			$result = aws organizations attach-policy --policy-id $policy.Id --target-id $retiredOu
		}
	}
	Write-Host("Created SCPs and attached them to OUs")
	
	if($allFixes -eq $false) {
		exit
	}
}


# Do not honor all fixes - force explicit use
if ($deleteLegacy) {
	# Delete legacy lambda
	$result = aws lambda delete-function --function-name DeleteExpiredServiceAccess
	
	# Explicitly define what to retire - no chance of filtering or code logic retiring the wrong thing
	$policiesToRetire = @()
	$policiesToRetire += ("arn:aws:iam::{0}:policy/WSUPolicy_ComputeAdministrator_USWest2_MFAAge" -f $accountId)
	$policiesToRetire += ("arn:aws:iam::{0}:policy/WSUPolicy_SecurityGroupIngress_USWest2_MFAAge" -f $accountId)
	$policiesToRetire += ("arn:aws:iam::{0}:policy/WSUPolicy_AccountDisableAll_Global" -f $accountId)
	$policiesToRetire += ("arn:aws:iam::{0}:policy/WSUPolicy_IdentityAdministrator_Global_MFAAge" -f $accountId)
	$policiesToRetire += ("arn:aws:iam::{0}:policy/WSUPolicy_SecurityAdministrator_USWest2_MFAAge" -f $accountId)
	$policiesToRetire += ("arn:aws:iam::{0}:policy/WSUPolicy_SecurityGroupRevokeIngress_Lambda" -f $accountId)
	$policiesToRetire += ("arn:aws:iam::{0}:policy/WSUPolicy_FinanceAdministrator_USWest2_MFAAge" -f $accountId)
	$policiesToRetire += ("arn:aws:iam::{0}:policy/WSUPolicy_DeveloperAdministrator_USWest2_MFAAge" -f $accountId)
	
	# Get deny policy
	$denyAllPolicyFile = Get-Childitem -filter "iam-deny-all-policy.json"
	$denyAllPolicy = Get-Content $denyAllPolicyFile.FullName -raw
	$denyAllPolicy = $denyAllPolicy.Replace('"', '\"')
	
	# For each policy, check for max versions, delete oldest, and create new version
	$policiesToRetire | Foreach-Object {
		$versions = aws iam list-policy-versions --policy-arn $_
		$versions = ConvertFrom-Json($versions -join "")
		$versions = $versions.Versions
		
		# Remove the oldest policy version
		if ($versions.Count -eq 5) {
			 aws iam delete-policy-version --policy-arn $_ --version-id $versions[4].VersionId
		}
		
		# Create a default version of the legacy IAM policies that denies all access. (leave group/role/identities intact so it is easy to fix if this breaks something by revertng policy versions)
		$result = aws iam create-policy-version --policy-arn $_ --policy-document $denyAllPolicy --set-as-default
		Start-Sleep 1
	}
	
	Write-Host("Removed legacy baseline constructs")
	exit
}
Start-Sleep 1

if ($acceptSecurityHubInvitation -or $allFixes) {
	if($securityHubAccountId.Length -eq 0) {
		Write-Host("Accept Security Hub invitiation elected but no hub ID specified.")
		exit
	}
	
	$findingsRaw = aws securityhub get-findings --filters '{\"WorkflowStatus\": [{\"Value\": \"NEW\", \"Comparison\": \"EQUALS\"}]}' --max-items 100
	$findingsString = $findingsRaw -join ""
	$findings = (ConvertFrom-Json -InputObject $findingsString).Findings
	$i = 1

	while ($findings.Count -gt 0) {
		
		$count = $findings.Count
		$identifiers = @()

		foreach ($f in $findings) {
			$id = $f.Id.ToString()
			$arn = $f.ProductArn.ToString()
			$identifier = @"
{\"Id\": \"$id\", \"ProductArn\": \"$arn\"}
"@
			$identifiers += $identifier
		}

		$identifiers = $identifiers -join ","
		$exec = @"
aws securityhub batch-update-findings --finding-identifiers '[$identifiers]' --note '{\"Text\": \"Resolving stale findings.\", \"UpdatedBy\": \"bbonner\"}' --severity '{\"Label\": \"LOW\"}' --workflow '{\"Status\": \"RESOLVED\"}'
"@

		$output = Invoke-Expression $exec
		$output.UnprocessedFindings
		
		Write-Host ("Purged {0} findings" -f ($i*100).ToString())
		$i = $i + 1
		
		$findingsRaw = aws securityhub get-findings --filters '{\"WorkflowStatus\": [{\"Value\": \"NEW\", \"Comparison\": \"EQUALS\"}]}' --max-items 100
		$findingsString = $findingsRaw -join ""
		$findings = (ConvertFrom-Json -InputObject $findingsString).Findings
	}

	$invitations = aws securityhub list-invitations
	$invitations = $invitations -join ""
	
	if ($invitations.Length -gt 0) {
		$invitations = ConvertFrom-Json($invitations)
		$invitations = $invitations.Invitations
		
		$invitations | Foreach-Object {
			if ($_.AccountId -eq $securityHubAccountId) {
				aws securityhub accept-administrator-invitation --administrator-id $_.AccountId --invitation-id $_.InvitationId
				Write-Host("Accepted security hub invitation.")
			}
			Start-Sleep 1
		}
	}
	
	Write-Host("Security Hub fixes applied.")
	
	if($allFixes -eq $false) {
		exit
	}
}
Start-Sleep 1

if ($enableMacie -or $allFixes) {
	$result = aws macie2 enable-macie --finding-publishing-frequency FIFTEEN_MINUTES --status ENABLED
	$securityHubConfigurationFile = Get-Childitem -filter "macie-security-hub-configuration.json"
	$securityHubConfiguration = Get-Content $securityHubConfigurationFile.FullName -raw
	$securityHubConfiguration = $securityHubConfiguration.Replace('"', '\"')
	
	$result = aws macie2 put-findings-publication-configuration --security-hub-configuration $securityHubConfiguration
	Write-Host("Enabled Macie")
	
	if($allFixes -eq $false) {
		exit
	}
}
Start-Sleep 1

if ($rotateKmsKeys -or $allFixes) {
	$kmsKeys = aws kms list-keys
	$kmsKeys = ConvertFrom-Json($kmsKeys -join "")
	$kmsKeys = $kmsKeys.Keys

	$kmsKeys | Foreach-Object {
		$key = aws kms describe-key --key-id $_.KeyId
		$key = ConvertFrom-Json($key -join "")
		$key = $key.KeyMetaData
		
		if ($key.KeyManager -eq "CUSTOMER") {
			$status = aws kms get-key-rotation-status --key-id $key.KeyId
			$status = ConvertFrom-Json($status -join "")
			$status = $status.KeyRotationEnabled
			
			if ($status -eq $false) {
				# no output expected
				$result = aws kms enable-key-rotation --key-id $key.KeyId
				Write-Host("Enabled rotation for {0}." -f $key.KeyId)
			}
		}
		Start-Sleep 1
	}
	Write-Host("Enabled key rotation for all customer keys.")
	
	if($allFixes -eq $false) {
		exit
	}
}
Start-Sleep 1

if ($bucketLogging -or $allFixes) {
	$buckets = aws s3api list-buckets
	$buckets = ConvertFrom-Json($buckets -join "")
	$buckets = $buckets.Buckets
	
	$logging = $false
	$buckets | Foreach-Object {
		$result = aws s3api get-bucket-logging --bucket $_.Name
		
		if ($result.Length -ne 0) {
			$logging = $true
		}
		Start-Sleep 1
	}
	
	if ($logging -eq $false) {
		$bucketName = "{0}-s3-server-access-logging" -f $alias

		$locationConstraintFile = Get-Childitem -filter "s3-location-constraint.json"
		$locationConstraint = Get-Content $locationConstraintFile.FullName -raw
		$locationConstraint = $locationConstraint.Replace('"', '\"')
		
		$bucketPolicyFile = Get-Childitem -filter "s3-bucket-logging-policy.json"
		$bucketPolicy = Get-Content $bucketPolicyFile.FullName -raw
		$bucketPolicy = $bucketPolicy.Replace('"', '\"')
		$bucketPolicy = $bucketPolicy.Replace('[BUCKET-NAME]', $bucketName)
		$bucketPolicy = $bucketPolicy.Replace('[ACCOUNT-ID]', $accountId)
		
		$bucketLoggingStatusFile = Get-Childitem -filter "s3-bucket-logging-status.json"
		$bucketLoggingStatus = Get-Content $bucketLoggingStatusFile.FullName -raw
		$bucketLoggingStatus = $bucketLoggingStatus.Replace('"', '\"')
		$bucketLoggingStatus = $bucketLoggingStatus.Replace('[BUCKET-NAME]', $bucketName)

		$result = aws s3api create-bucket --bucket $bucketName --region us-west-2 --create-bucket-configuration $locationConstraint
		$result = aws s3api put-bucket-policy --bucket $bucketName --policy $bucketPolicy

		$buckets | Foreach-Object {
			if ($_.Name -ne $bucketName) {
				$result = aws s3api put-bucket-logging --bucket $_.Name --bucket-logging-status $bucketLoggingStatus
				$result
			}
			Start-Sleep 1
		}
		
		$logging = $true
		$buckets | Foreach-Object {
			$result = aws s3api get-bucket-logging --bucket $_.Name
			
			if ($result.Length -eq 0) {
				$logging = $false
			}
		}
		
		if ($logging) {
			Write-Host("Logging enabled on all buckets.")
		} else {
			Write-Host("Logging not enabled on all buckets.")
		}
	} else {
			Write-Host("One or more buckets already has logging enabled - manually fix!")
			Write-Host("One or more buckets already has logging enabled - manually fix!")
			Write-Host("One or more buckets already has logging enabled - manually fix!")
	}
	
	Write-Host("Bucket logging fixes processed.")
	
	if($allFixes -eq $false) {
		exit
	}
}
Start-Sleep 1

if ($encryptBuckets -or $allFixes) {
	$encryptionConfigurationFile = Get-Childitem -filter "s3-encryption-configuration.json"
	$encryptionConfiguration = Get-Content $encryptionConfigurationFile.FullName -raw
	$encryptionConfiguration = $encryptionConfiguration.Replace('"', '\"')
	
	$buckets = aws s3api list-buckets
	$buckets = ConvertFrom-Json($buckets -join "")
	$buckets = $buckets.Buckets
	
	$buckets | Foreach-Object {
		$result = aws s3api get-bucket-encryption --bucket $_.Name
		
		if ($result.Length -eq 0) {
			Write-Host("Beginning encryption.")
			$result = aws s3api put-bucket-encryption --bucket $_.Name --server-side-encryption-configuration $encryptionConfiguration
			$result
			Write-Host("Encrypted bucket {0}" -f $_.Name)
		}
		Start-Sleep 1
	}
	
	Write-Host("Bucket encryption fixes applied.")
	
	if($allFixes -eq $false) {
		exit
	}
}
Start-Sleep 1

if ($publicAccountAccessBlock -or $allFixes) {
	$result = aws s3control get-public-access-block --account-id $accountId
	
	if ($result.Length -eq 0) {
		$accessConfigurationFile = Get-Childitem -filter "s3-public-access-block-configuration.json"
		$accessConfiguration = Get-Content $accessConfigurationFile.FullName -raw
		$accessConfiguration = $accessConfiguration.Replace('"', '\"')
	
		$result = aws s3control put-public-access-block --account-id $accountId --public-access-block-configuration $accessConfiguration
		$result = aws s3control get-public-access-block --account-id $accountId
		
		if ($result.Length -ne 0) {
			Write-Host("S3 account public block in place.")
		}
	} else {
		Write-Host("S3 account public block already in place.")
	}
	
	Write-Host("Public account S3 block fix processed.")
	
	if($allFixes -eq $false) {
		exit
	}
}
Start-Sleep 1

if ($publicBucketAccessBlock -or $allFixes) {
	$buckets = aws s3api list-buckets
	$buckets = ConvertFrom-Json($buckets -join "")
	$buckets = $buckets.Buckets
	
	$accessConfigurationFile = Get-Childitem -filter "s3-public-access-block-configuration.json"
	$accessConfiguration = Get-Content $accessConfigurationFile.FullName -raw
	$accessConfiguration = $accessConfiguration.Replace('"', '\"')
			
	$buckets | Foreach-Object {
		$result = aws s3api get-public-access-block --bucket $_.Name
		
		if ($result.Length -eq 0) {
			$result = aws s3api put-public-access-block --bucket $_.Name --public-access-block-configuration $accessConfiguration
			$result = aws s3api get-public-access-block --bucket $_.Name
			
			if ($result.Length -ne 0) {
				Write-Host("S3 bucket public block in place.")
			}
		} else {
			Write-Host("S3 bucket public block already in place.")
		}
		Start-Sleep 1
	}
	
	Write-Host("Public access bucket block fix processed.")
	
	if($allFixes -eq $false) {
		exit
	}
}
Start-Sleep 1

if ($s3SecureTransport -or $allFixes) {
	$buckets = aws s3api list-buckets
	$buckets = ConvertFrom-Json($buckets -join "")
	$buckets = $buckets.Buckets
	
	# Get the file and file contents
	$transportPolicyFile = Get-Childitem -filter "s3-bucket-secure-transport-policy.json"
	$transportPolicy = Get-Content $transportPolicyFile.FullName -raw
			
	$buckets | Foreach-Object {
		$policy = aws s3api get-bucket-policy --bucket $_.Name	# get the bucket policy as a string array
		$policy = $policy -join "" # create a single JSON string of the policy
		
		$transportStatement = $transportPolicy.Replace('[BUCKET-NAME]', $_.Name) # set the bucket name
		$transportStatement = ConvertFrom-Json($transportStatement) # create an object of the transport statement
		
		if ($policy.Length -eq 0) {
			$policy = ConvertTo-Json($transportStatement) -depth 20	# convert the object to JSON string
			$policy = "{0}{1}{2}" -f '{"Version": "2012-10-17","Statement": [', $policy, "]}" # Add the start and end of of policy statement
		} elseif ($policy -like '*SecureTransport*') {
			Write-Host("S3 bucket {0} secure transport already set." -f $_.Name)	# Skip buckets that already have this policy
			return
		} else {
			# The variable names are confusing due to the weird sub-objects of powershell
			$statements = ConvertFrom-Json($policy)					# Unpack the bucket policy
			$statements = ConvertFrom-Json($statements.Policy)		# Unpack the sub-object
			#$statements = ConvertFrom-Json($statements.Statement)	# Unpack the statements
			#$statements
			$statements.Statement = $statements.Statement + $transportStatement #Add the transport statement
			$policy = ConvertTo-Json($statements) -depth 20 #Convert back to JSON
		}
		
		# Escape the double quotes for execution and put the policy on the bucket
		$policy = $policy.Replace('"', '\"')
		$result = aws s3api put-bucket-policy --bucket $_.Name --policy $policy
		Write-Host("S3 bucket {0} secure transport set." -f $_.Name)
		Start-Sleep 1
	}
	
	Write-Host("Secure bucket transport fix processed.")
	
	if($allFixes -eq $false) {
		exit
	}
}