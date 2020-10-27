## PenTest:IAMUser/KaliLinux

**An API was invoked from a Kali Linux EC2 machine.**

**OPSEC Guidelines**

**Default severity: Medium**

This finding informs you that a machine running Kali Linux is making API calls using credentials that belong to the listed AWS account in your environment. Kali Linux is a popular penetration testing tool that security professionals use to identify weaknesses in EC2 instances that require patching. Attackers also use this tool to find EC2 configuration weaknesses and gain unauthorized access to your AWS environment.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## PenTest:IAMUser/ParrotLinux

**OPSEC Guidelines**

**An API was invoked from a Parrot Security Linux machine.**

**Default severity: Medium**

This finding informs you that a machine running Parrot Security Linux is making API calls using credentials that belong to the listed AWS account in your environment. Parrot Security Linux is a popular penetration testing tool that security professionals use to identify weaknesses in EC2 instances that require patching. Attackers also use this tool to find EC2 configuration weaknesses and gain unauthorized access to your AWS environment.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## PenTest:IAMUser/PentooLinux

**OPSEC Guidelines**

**An API was invoked from a Pentoo Linux machine.**

**Default severity: Medium**

This finding informs you that a machine running Pentoo Linux is making API calls using credentials that belong to the listed AWS account in your environment. Pentoo Linux is a popular penetration testing tool that security professionals use to identify weaknesses in EC2 instances that require patching. Attackers also use this tool to find EC2 configuration weaknesses and gain unauthorized access to your AWS environment.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Persistence:IAMUser/NetworkPermissions

**OPSEC Guidelines**

**An IAM entity invoked an API commonly used to change the network access permissions for security groups, routes, and ACLs in your AWS account.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding indicates that a specific principal (AWS account root user, IAM role, or IAM user) in your AWS environment is exhibiting behavior that is different from the established baseline. This principal has no prior history of invoking this API.

This finding is triggered when network configuration settings are changed under suspicious circumstances, such as when a principal invokes the¬†CreateSecurityGroup¬†API with no prior history of doing so. Attackers often attempt to change security groups to allow certain inbound traffic on various ports to improve their ability to access an EC2 instance.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Persistence:IAMUser/ResourcePermissions

**OPSEC Guidelines**

**A principal invoked an API commonly used to change the security access policies of various resources in your AWS account.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked is using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding indicates that a specific principal (AWS account root user, IAM role, or IAM user) in your AWS environment is exhibiting behavior that is different from the established baseline. This principal has no prior history of invoking this API.

This finding is triggered when a change is detected to policies or permissions attached to AWS resources, such as when a principal in your AWS environment invokes the¬†PutBucketPolicy¬†API with no prior history of doing so. Some services, such as Amazon S3, support resource-attached permissions that grant one or more principals access to the resource. With stolen credentials, attackers can change the policies attached to a resource in order to gain access to that resource.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Persistence:IAMUser/UserPermissions

**OPSEC Guidelines**

**A principal invoked an API commonly used to add, modify, or delete IAM users, groups or policies in your AWS account.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding indicates that a specific principal (AWS account root user, IAM role, or IAM user) in your AWS environment is exhibiting behavior that is different from the established baseline. This principal has no prior history of invoking this API.

This finding is triggered by suspicious changes to the user-related permissions in your AWS environment, such as when a principal in your AWS environment invokes the¬†AttachUserPolicy¬†API with no prior history of doing so. Attackers may use stolen credentials to create new users, add access policies to existing users, or create access keys to maximize their access to an account, even if their original access point is closed. For example, the owner of the account might notice that a particular IAM user or password was stolen and delete it from the account. However, they might not delete other users that were created by a fraudulently created admin principal, leaving their AWS account accessible to the attacker.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Policy:IAMUser/RootCredentialUsage

**OPSEC Guidelines**

**An API was invoked using root credentials.**

**Default severity: Low**

This finding informs you that the root credentials of the listed AWS account in your environment are being used to make requests to AWS services. It is recommended that users never use root credentials to access AWS services. Instead, AWS services should be accessed using least privilege temporary credentials from AWS Security Token Service (STS). For situations where STS is not supported, IAM user credentials are recommended. For more information, see¬†[IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

**Note**

If S3 threat detection is enabled for the account this finding may be generated in response to attempts to run S3 data plane operations on S3 resources using the root credentials of the AWS account. The API call used will be listed in the finding details. If S3 threat detection is not enabled this finding can only be triggered by Event log API&#39;s. For more information on S3 threat detection see¬†[Amazon S3 protection in Amazon GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/s3_detection.html).

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## PrivilegeEscalation:IAMUser/AdministrativePermissions

**OPSEC Guidelines**

**A principal has attempted to assign a highly permissive policy to themselves.**

**Default severity: Low\***

**Note**

This finding&#39;s severity is Low if the attempt at privilege escalation was unsuccessful, and Medium if the attempt at privilege escalation was successful.

This finding indicates that a specific IAM entity in your AWS environment is exhibiting behavior that can be indicative of a privilege escalation attack. This finding is triggered when an IAM user or role attempts to assign a highly permissive policy to themselves. If the user or role in question is not meant to have administrative privileges, either the user&#39;s credentials may be compromised or the role&#39;s permissions may not be configured properly.

Attackers will use stolen credentials to create new users, add access policies to existing users, or create access keys to maximize their access to an account even if their original access point is closed. For example, the owner of the account might notice that a particular IAM user or password was stolen and delete it from the account, but might not delete other users that were created by a fraudulently created admin principal, leaving their AWS account still accessible to the attacker.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Recon:IAMUser/MaliciousIPCaller

**OPSEC Guidelines**

**An API was invoked from a known malicious IP address.**

**Default severity: Medium**

This finding informs you that an API operation that can list or describe AWS resources in an account within your environment was invoked from an IP address that is included on an internal threat list. generates findings based off of third-party partner threat lists. The threat list used to generate this finding will be listed in the finding&#39;s details. An attacker might use stolen credentials to perform this type of reconnaissance of your AWS resources in order to find more valuable credentials or determine the capabilities of the credentials they already have.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Recon:IAMUser/MaliciousIPCaller.Custom

**OPSEC Guidelines**

**An API was invoked from a known malicious IP address.**

**Default severity: Medium**

This finding informs you that an API operation that can list or describe AWS resources in an account within your environment was invoked from an IP address that is included on a custom threat list. The threat list used will be listed in the finding&#39;s details. An attacker might use stolen credentials to perform this type of reconnaissance of your AWS resources in order to find more valuable credentials or determine the capabilities of the credentials they already have.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Recon:IAMUser/NetworkPermissions

**OPSEC Guidelines**

**A principal invoked an API commonly used to change the network access permissions for security groups, routes, and ACLs in your AWS account.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding indicates that a specific principal (AWS account root user, IAM role, or IAM user) in your AWS environment is exhibiting behavior that is different from the established baseline. This principal has no prior history of invoking this API.

This finding is triggered when resource access permissions in your AWS account are probed under suspicious circumstances. For example, if a principal invoked the¬†DescribeInstances¬†API with no prior history of doing so. An attacker might use stolen credentials to perform this type of reconnaissance of your AWS resources in order to find more valuable credentials or determine the capabilities of the credentials they already have.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Recon:IAMUser/ResourcePermissions

**OPSEC Guidelines**

**A principal invoked an API commonly used to change the security access policies of various resources in your AWS account.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding indicates that a specific principal (AWS account root user, IAM role, or IAM user) in your AWS environment is exhibiting behavior that is different from the established baseline. This principal has no prior history of invoking this API.

This finding is triggered when resource access permissions in your AWS account are probed under suspicious circumstances. For example, if a principal invoked the¬†DescribeInstances¬†API with no prior history of doing so. An attacker might use stolen credentials to perform this type of reconnaissance of your AWS resources in order to find more valuable credentials or determine the capabilities of the credentials they already have.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Recon:IAMUser/TorIPCaller

**OPSEC Guidelines**

**An API was invoked from a Tor exit node IP address.**

**Default severity: Medium**

This finding informs you that an API operation that can list or describe AWS resources in an account within your environment was invoked from a Tor exit node IP address. Tor is software for enabling anonymous communication. It encrypts and randomly bounces communications through relays between a series of network nodes. The last Tor node is called the exit node. An attacker would use Tor to mask their true identity.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Recon:IAMUser/UserPermissions

**OPSEC Guidelines**

**A principal invoked an API commonly used to add, modify, or delete IAM users, groups or policies in your AWS account.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding is triggered when user permissions in your AWS environment are probed under suspicious circumstances. For example, if a principal (AWS account root user, IAM role, or IAM user) invoked the¬†ListInstanceProfilesForRole¬†API with no prior history of doing so. An attacker might use stolen credentials to perform this type of reconnaissance of your AWS resources in order to find more valuable credentials or determine the capabilities of the credentials they already have.

This finding indicates that a specific principal in your AWS environment is exhibiting behavior that is different from the established baseline. This principal has no prior history of invoking this API in this way.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## ResourceConsumption:IAMUser/ComputeResources

**OPSEC Guidelines**

**A principal invoked an API commonly used to launch Compute resources like EC2 Instances.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding is triggered when EC2 instances in the listed account within your AWS environment are launched under suspicious circumstances. This finding indicates that a specific principal in your AWS environment is exhibiting behavior that is different from the established baseline; for example, if a principal (AWS account root user, IAM role, or IAM user) invoked the¬†RunInstances¬†API with no prior history of doing so. This might be an indication of an attacker using stolen credentials to steal compute time (possibly for cryptocurrency mining or password cracking). It can also be an indication of an attacker using an EC2 instance in your AWS environment and its credentials to maintain access to your account.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Stealth:IAMUser/CloudTrailLoggingDisabled

**OPSEC Guidelines**

**AWS CloudTrail trail was disabled.**

**Default severity: Low**

This finding informs you that a CloudTrail trail within your AWS environment was disabled. This can be an attacker&#39;s attempt to disable logging to cover their tracks by eliminating any trace of their activity while gaining access to your AWS resources for malicious purposes. This finding can be triggered by a successful deletion or update of a trail. This finding can also be triggered by a successful deletion of an S3 bucket that stores the logs from a trail that is associated with GuardDuty.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Stealth:IAMUser/LoggingConfigurationModified

**OPSEC Guidelines**

**A principal invoked an API commonly used to stop CloudTrail Logging, delete existing logs, and otherwise eliminate traces of activity in your AWS account.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding is triggered when the logging configuration in the listed AWS account within your environment is modified under suspicious circumstances. This finding informs you that a specific principal in your AWS environment is exhibiting behavior that is different from the established baseline; for example, if a principal (AWS account root user, IAM role, or IAM user) invoked the¬†StopLogging¬†API with no prior history of doing so. This can be an indication of an attacker trying to cover their tracks by eliminating any trace of their activity.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Stealth:IAMUser/PasswordPolicyChange

**OPSEC Guidelines**

**Account password policy was weakened.**

**Default severity: Low**

The AWS account password policy was weakened on the listed account within your AWS environment. For example, it was deleted or updated to require fewer characters, not require symbols and numbers, or required to extend the password expiration period. This finding can also be triggered by an attempt to update or delete your AWS account password policy. The AWS account password policy defines the rules that govern what kinds of passwords can be set for your IAM users. A weaker password policy permits the creation of passwords that are easy to remember and potentially easier to guess, thereby creating a security risk.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## UnauthorizedAccess:IAMUser/ConsoleLogin

**OPSEC Guidelines**

**An unusual console login by a principal in your AWS account was observed.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding is triggered when a console login is detected under suspicious circumstances. For example, if a principal with no prior history of doing so, invoked the ConsoleLogin API from a never-before-used client or an unusual location. This could be an indication of stolen credentials being used to gain access to your AWS account, or a valid user accessing the account in an invalid or less secure manner (for example, not over an approved VPN).

This finding informs you that a specific principal in your AWS environment is exhibiting behavior that is different from the established baseline. This principal has no prior history of login activity using this client application from this specific location.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B

**OPSEC Guidelines**

**Multiple worldwide successful console logins were observed.**

**Default severity: Medium**

This finding informs you that multiple successful console logins for the same IAM user were observed around the same time in various geographical locations. Such anomalous and risky access location patterns indicate potential unauthorized access to your AWS resources.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration

**OPSEC Guidelines**

**Credentials that were created exclusively for an EC2 instance through an Instance launch role are being used from an external IP address.**

**Default severity: High**

This finding informs you of attempts to run AWS API operations from a host outside of EC2, using temporary AWS credentials that were created on an EC2 instance in your AWS environment. The listed EC2 instance might be compromised, and the temporary credentials from this instance might have been exfiltrated to a remote host outside of AWS. AWS does not recommend redistributing temporary credentials outside of the entity that created them (for example, AWS applications, EC2, or Lambda). However, authorized users can export credentials from their EC2 instances to make legitimate API calls. To rule out a potential attack and verify the legitimacy of the activity, contact the IAM user to whom these credentials are assigned.

**Note**

If S3 threat detection is enabled for the account this finding may be generated in response to attempts to run S3 data plane operations on the S3 resources using EC2 credentials. The API call used will be listed in the finding details. If S3 threat detection is not enabled this finding can only be triggered by Event log API&#39;s. For more information on S3 threat detection see¬†[Amazon S3 protection in Amazon GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/s3_detection.html).

**Remediation recommendations:**

This finding is generated when networking is configured to route internet traffic such that it egresses from an on-premises gateway rather than from a VPC Internet Gateway (IGW). Common configurations, such as using ,¬†[AWS Outposts](https://docs.aws.amazon.com/outposts/latest/userguide/), or VPC VPN connections, can result in traffic routed this way. If this is expected behavior, it&#39;s recommended that you use suppression rules in and create a rule that consists of two filter criteria. The first criteria is¬† **finding type** , which should be¬†UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration. The second filter criteria is¬† **API caller IPv4 Address** ¬†with the IP address or CIDR range of your on-premises internet gateway. To learn more about creating suppression rules see¬†[Suppression rules](https://docs.aws.amazon.com/guardduty/latest/ug/findings_suppression-rule.html).

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## UnauthorizedAccess:IAMUser/MaliciousIPCaller

**OPSEC Guidelines**

**An API was invoked from a known malicious IP address.**

**Default severity: Medium**

This finding informs you that an API operation (for example, an attempt to launch an EC2 instance, create a new IAM user, modify your AWS privileges) was invoked from a known malicious IP address. This can indicate unauthorized access to AWS resources within your environment.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom

**OPSEC Guidelines**

**An API was invoked from an IP address on a custom threat list.**

**Default severity: Medium**

This finding informs you that an API operation (for example, an attempt to launch an EC2 instance, create a new IAM user, modify AWS privileges) was invoked from an IP address that is included on a threat list that you uploaded. In , a threat list consists of known malicious IP addresses. generates findings based on uploaded threat lists. This can indicate unauthorized access to your AWS resources within your environment.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## UnauthorizedAccess:IAMUser/TorIPCaller

**OPSEC Guidelines**

**An API was invoked from a Tor exit node IP address.**

**Default severity: Medium**

This finding informs you that an API operation (for example, an attempt to launch an EC2 instance, create a new IAM user, or modify your AWS privileges) was invoked from a Tor exit node IP address. Tor is software for enabling anonymous communication. It encrypts and randomly bounces communications through relays between a series of network nodes. The last Tor node is called the exit node. This can indicate unauthorized access to your AWS resources with the intent of hiding the attacker&#39;s true identity.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).
