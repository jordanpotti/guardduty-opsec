# GuardDuty Opsec Considerations

GuardDuty is AWS's security monitoring service that analyzes VPC Flow Logs, AWS CloudTrail management event logs, Cloudtrail S3 event logs and DNS logs. 

Typically, its the lowest bar for monitoring in an AWS environment, but can and does trip up attackers, pentesters and red teams. 


| FINDING TYPE  | THREAT PURPOSE | RESOURCE | SEVERITY | 
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | -------- | -------- | 
| [Backdoor:EC2/C&CActivity.B!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-ccactivitybdns) | Backdoor | EC2 | High |
| [Backdoor:EC2/DenialOfService.Dns](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofservicedns) | Backdoor | EC2 | High |
| [Backdoor:EC2/DenialOfService.Tcp](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofservicetcp) | Backdoor | EC2 | High |
| [Backdoor:EC2/DenialOfService.Udp](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofserviceudp) | Backdoor | EC2 | High |
| [Backdoor:EC2/DenialOfService.UdpOnTcpPorts](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofserviceudpontcpports) | Backdoor | EC2 | High |
| [Backdoor:EC2/DenialOfService.UnusualProtocol](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofserviceunusualprotocol) | Backdoor | EC2 | High |
| [Backdoor:EC2/Spambot](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-spambot) | Backdoor | EC2 | Medium |
| [Behavior:EC2/NetworkPortUnusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#behavior-ec2-networkportunusual) | Behavior | EC2 | Medium |
| [Behavior:EC2/TrafficVolumeUnusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#behavior-ec2-trafficvolumeunusual) | Behavior | EC2 | Medium |
| [CryptoCurrency:EC2/BitcoinTool.B](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#cryptocurrency-ec2-bitcointoolb) | CryptoCurrency | EC2 | High |
| [CryptoCurrency:EC2/BitcoinTool.B!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#cryptocurrency-ec2-bitcointoolbdns) | CryptoCurrency | EC2 | High |
| [Impact:EC2/WinRMBruteForce](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#impact-ec2-winrmbruteforce) | Impact | EC2 | High |
| [Impact:EC2/PortSweep](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#impact-ec2-portsweep) | Impact | EC2 | High |
| [Recon:EC2/PortProbeEMRUnprotectedPort](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portprobeemrunprotectedport) | Recon | EC2 | High |
| [Recon:EC2/PortProbeUnprotectedPort](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portprobeunprotectedport) | Recon | EC2 | Low\* |
| [Recon:EC2/Portscan](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portscan) | Recon | EC2 | Medium |
| [Trojan:EC2/BlackholeTraffic](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-blackholetraffic) | Trojan | EC2 | Medium |
| [Trojan:EC2/BlackholeTraffic!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-blackholetrafficdns) | Trojan | EC2 | Medium |
| [Trojan:EC2/DGADomainRequest.B](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-dgadomainrequestb) | Trojan | EC2 | High |
| [Trojan:EC2/DGADomainRequest.C!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-dgadomainrequestcdns) | Trojan | EC2 | High |
| [Trojan:EC2/DNSDataExfiltration](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-dnsdataexfiltration) | Trojan | EC2 | High |
| [Trojan:EC2/DriveBySourceTraffic!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-drivebysourcetrafficdns) | Trojan | EC2 | Medium |
| [Trojan:EC2/DropPoint](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-droppoint) | Trojan | EC2 | Medium |
| [Trojan:EC2/DropPoint!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-droppointdns) | Trojan | EC2 | High |
| [Trojan:EC2/PhishingDomainRequest!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-phishingdomainrequestdns) | Trojan | EC2 | High |
| [UnauthorizedAccess:EC2/MaliciousIPCaller.Custom](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-maliciousipcallercustom) | UnauthorizedAccess | EC2 | Medium |
| [UnauthorizedAccess:EC2/MetadataDNSRebind](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-metadatadnsrebind) | UnauthorizedAccess | EC2 | High |
| [UnauthorizedAccess:EC2/RDPBruteForce](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-rdpbruteforce) | UnauthorizedAccess | EC2 | Low\* |
| [UnauthorizedAccess:EC2/SSHBruteForce](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-sshbruteforce) | UnauthorizedAccess | EC2 | Low\* |
| [UnauthorizedAccess:EC2/TorClient](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-torclient) | UnauthorizedAccess | EC2 | High |
| [UnauthorizedAccess:EC2/TorRelay](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-torrelay) | UnauthorizedAccess | EC2 | High |
| [PenTest:IAMUser/KaliLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-kalilinux) | PenTest | IAM | Medium |
| [PenTest:IAMUser/ParrotLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-parrotlinux) | PenTest | IAM | Medium |
| [PenTest:IAMUser/PentooLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-pentoolinux) | PenTest | IAM | Medium |
| [Persistence:IAMUser/NetworkPermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#persistence-iam-networkpermissions) | Persistence | IAM | Medium\* |
| [Persistence:IAMUser/ResourcePermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#persistence-iam-resourcepermissions) | Persistence | IAM | Medium\* |
| [Persistence:IAMUser/UserPermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#persistence-iam-userpermissions) | Persistence | IAM | Medium\* |
| [Policy:IAMUser/RootCredentialUsage](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#policy-iam-rootcredentialusage) | Policy | IAM | Low |
| [PrivilegeEscalation:IAMUser/AdministrativePermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#privilegeescalation-iam-administrativepermissions) | PrivilegeEscalation | IAM | Low\* |
| [Recon:IAMUser/MaliciousIPCaller](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-maliciousipcaller) | Recon | IAM | Medium |
| [Recon:IAMUser/MaliciousIPCaller.Custom](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-maliciousipcallercustom) | Recon | IAM | Medium |
| [Recon:IAMUser/NetworkPermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-networkpermissions) | Recon | IAM | Medium\* |
| [Recon:IAMUser/ResourcePermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-resourcepermissions) | Recon | IAM | Medium\* |
| [Recon:IAMUser/TorIPCaller](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-toripcaller) | Recon | IAM | Medium |
| [Recon:IAMUser/UserPermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-userpermissions) | Recon | IAM | Medium\* |
| [ResourceConsumption:IAMUser/ComputeResources](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#resourceconsumption-iam-computeresources) | ResourceConsumption | IAM | Medium\* |
| [Stealth:IAMUser/CloudTrailLoggingDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-cloudtrailloggingdisabled) | Stealth | IAM | Low |
| [Stealth:IAMUser/LoggingConfigurationModified](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-loggingconfigurationmodified) | Stealth | IAM | Medium\* |
| [Stealth:IAMUser/PasswordPolicyChange](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-passwordpolicychange) | Stealth | IAM | Low |
| [UnauthorizedAccess:IAMUser/ConsoleLogin](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-consolelogin) | UnauthorizedAccess | IAM | Medium\* |
| [UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-consoleloginsuccessb) | UnauthorizedAccess | IAM | Medium |
| [UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-instancecredentialexfiltration) | UnauthorizedAccess | IAM | High |
| [UnauthorizedAccess:IAMUser/MaliciousIPCaller](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-maliciousipcaller) | UnauthorizedAccess | IAM | Medium |
| [UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-maliciousipcallercustom) | UnauthorizedAccess | IAM | Medium |
| [UnauthorizedAccess:IAMUser/TorIPCaller](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-toripcaller) | UnauthorizedAccess | IAM | Medium |
| [Discovery:S3/BucketEnumeration.Unusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-bucketenumerationunusual) | Discovery | S3 | Medium |
| [Discovery:S3/MaliciousIPCaller.Custom](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-maliciousipcallercustom) | Discovery | S3 | High |
| [Discovery:S3/TorIPCaller](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-toripcaller) | Discovery | S3 | Medium |
| [Exfiltration:S3/ObjectRead.Unusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#exfiltration-s3-objectreadunusual) | Exfiltration | S3 | Medium |
| [Impact:S3/PermissionsModification.Unusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#impact-s3-permissionsmodificationunusual) | Impact | S3 | Medium |
| [Impact:S3/ObjectDelete.Unusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#impact-s3-objectdeleteunusual) | Impact | S3 | Medium |
| [PenTest:S3/KaliLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#pentest-s3-kalilinux) | PenTest | S3 | Medium |
| [PenTest:S3/ParrotLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#pentest-s3-parrotlinux) | PenTest | S3 | Medium |
| [PenTest:S3/PentooLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#pentest-s3-pentoolinux) | PenTest | S3 | Medium |
| [Policy:S3/AccountBlockPublicAccessDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-accountblockpublicaccessdisabled) | Policy | S3 | Low |
| [Policy:S3/BucketBlockPublicAccessDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketblockpublicaccessdisabled) | Policy | S3 | Low |
| [Policy:S3/BucketAnonymousAccessGranted](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketanonymousaccessgranted) | Policy | S3 | High |
| [Policy:S3/BucketPublicAccessGranted](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketpublicaccessgranted) | Policy | S3 | High |
| [Stealth:S3/ServerAccessLoggingDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#stealth-s3-serveraccessloggingdisabled) | Stealth | S3 | Low |
| [UnauthorizedAccess:S3/MaliciousIPCaller.Custom](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#unauthorizedaccess-s3-maliciousipcallercustom) | UnauthorizedAccess | S3 | High |
| [UnauthorizedAccess:S3/TorIPCaller](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#unauthorizedaccess-s3-toripcaller) | UnauthorizedAccess | S3 | High |


https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html


# EC2 Findings

## Backdoor:EC2/C&amp;CActivity.B!DNS

**An EC2 instance is querying a domain name that is associated with a known command and control server.**

**OPSEC Guidelines**

- Make sure your C2 servers are behind Load Balancers or redirectors.
- Leverage tools such as mod_rewrite to restrict and control expected traffic to your C2 servers.
- Use CDN's or Domain Fronting as redirectors. https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki#domain-fronting

**Default severity: High**

This finding informs you that the listed instance within your AWS environment is querying a domain name associated with a known command and control (C&amp;C) server. The listed instance might be compromised. Command and control servers are computers that issue commands to members of a botnet. A botnet is a collection of internet-connected devices which might include PCs, servers, mobile devices, and Internet of Things devices, that are infected and controlled by a common type of malware. Botnets are often used to distribute malware and gather misappropriated information, such as credit card numbers. Depending on the purpose and structure of the botnet, the C&amp;C server might also issue commands to begin a distributed denial-of-service (DDoS) attack.

**Note**

To test how generates this finding type, you can make a DNS request from your instance (using¬†dig¬†for Linux or¬†nslookup¬†for Windows) against a test domain¬†guarddutyc2activityb.com.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Backdoor:EC2/DenialOfService.Dns

**An EC2 instance is behaving in a manner that may indicate it is being used to perform a Denial of Service (DoS) attack using the DNS protocol.**

**OPSEC Guidelines**

- NA

**Default severity: High**

This finding informs you that the listed EC2 instance within your AWS environment is generating a large volume of outbound DNS traffic. This may indicate that the listed instance is compromised and being used to perform denial-of-service (DoS) attacks using DNS protocol.

**Note**

This finding detects DoS attacks only against publicly routable IP addresses, which are primary targets of DoS attacks.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Backdoor:EC2/DenialOfService.Tcp

**OPSEC Guidelines**

- NA

**An EC2 instance is behaving in a manner indicating it is being used to perform a Denial of Service (DoS) attack using the TCP protocol.**

**Default severity: High**

This finding informs you that the listed EC2 instance within your AWS environment is generating a large volume of outbound TCP traffic. This may indicate that the instance is compromised and being used to perform denial-of-service (DoS) attacks using TCP protocol.

**Note**

This finding detects DoS attacks only against publicly routable IP addresses, which are primary targets of DoS attacks.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Backdoor:EC2/DenialOfService.Udp

**OPSEC Guidelines**

- NA

**An EC2 instance is behaving in a manner indicating it is being used to perform a Denial of Service (DoS) attack using the UDP protocol.**

**Default severity: High**

This finding informs you that the listed EC2 instance within your AWS environment is generating a large volume of outbound UDP traffic. This may indicate that the listed instance is compromised and being used to perform denial-of-service (DoS) attacks using UDP protocol.

**Note**

This finding detects DoS attacks only against publicly routable IP addresses, which are primary targets of DoS attacks.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Backdoor:EC2/DenialOfService.UdpOnTcpPorts

**OPSEC Guidelines**

- NA

**An EC2 instance is behaving in a manner that may indicate it is being used to perform a Denial of Service (DoS) attack using the UDP protocol on a TCP port.**

**Default severity: High**

This finding informs you that the listed EC2 instance within your AWS environment is generating a large volume of outbound UDP traffic targeted to a port that is typically used for TCP communication. This may indicate that the listed instance is compromised and being used to perform a denial-of-service (DoS) attacks using UDP protocol on a TCP port.

**Note**

This finding detects DoS attacks only against publicly routable IP addresses, which are primary targets of DoS attacks.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Backdoor:EC2/DenialOfService.UnusualProtocol

**OPSEC Guidelines**

- NA

**An EC2 instance is behaving in a manner that may indicate it is being used to perform a Denial of Service (DoS) attack using an unusual protocol.**

**Default severity: High**

This finding informs you that the listed EC2 instance in your AWS environment is generating a large volume of outbound traffic from an unusual protocol type that is not typically used by EC2 instances, such as Internet Group Management Protocol. This may indicate that the instance is compromised and is being used to perform denial-of-service (DoS) attacks using an unusual protocol. This finding detects DoS attacks only against publicly routable IP addresses, which are primary targets of DoS attacks.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Backdoor:EC2/Spambot

**OPSEC Guidelines**

- If performing phishing using an internal SMTP relay accessible to a compromised EC2 instance, attempt to move to a server that _should_ be talking to the SMTP relay.

**An EC2 instance is exhibiting unusual behavior by communicating with a remote host on port 25.**

**Default severity: Medium**

This finding informs you that the listed EC2 instance in your AWS environment is communicating with a remote host on port 25. This behavior is unusual because this EC2 instance has no prior history of communications on port 25. Port 25 is traditionally used by mail servers for SMTP communications. This finding indicates your EC2 instance might be compromised for use in sending out spam.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Behavior:EC2/NetworkPortUnusual

**OPSEC Guidelines**

- Try to use common ports. 

**An EC2 instance is communicating with a remote host on an unusual server port.**

**Default severity: Medium**

This finding informs you that the listed EC2 instance in your AWS environment is behaving in a way that deviates from the established baseline. This EC2 instance has no prior history of communications on this remote port.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Behavior:EC2/TrafficVolumeUnusual

**OPSEC Guidelines**

- Stagger exfiltration of data in order to limit noticeable spikes. 

**An EC2 instance is generating unusually large amounts of network traffic to a remote host.**

**Default severity: Medium**

This finding informs you that the listed EC2 instance in your AWS environment is behaving in a way that deviates from the established baseline. This EC2 instance has no prior history of sending this much traffic to this remote host.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## CryptoCurrency:EC2/BitcoinTool.B

**OPSEC Guidelines**

- NA

**An EC2 instance is querying an IP address that is associated with cryptocurrency-related activity.**

**Default severity: High**

This finding informs you that the listed EC2 instance in your AWS environment is querying an IP Address that is associated with Bitcoin or other cryptocurrency-related activity. Bitcoin is a worldwide cryptocurrency and digital payment system. Besides being used as a reward for Bitcoin mining, Bitcoin can be exchanged for other currencies, products, and services.

**Remediation recommendations:**

If you use this EC2 instance to mine or manage cryptocurrency, or this instance is otherwise involved in blockchain activity, this finding could represented expected activity for your environment. If this is the case in your AWS environment, we recommend that you set up a suppression rule for this finding. The suppression rule should consist of two filter criteria. The first criteria should use the¬† **Finding type** ¬†attribute with a value of¬†CryptoCurrency:EC2/BitcoinTool.B!DNS. The second filter criteria should be the¬† **Instance ID** ¬†of the instance involved in blockchain activity. To learn more about creating suppression rules see¬†[Suppression rules](https://docs.aws.amazon.com/guardduty/latest/ug/findings_suppression-rule.html).

## CryptoCurrency:EC2/BitcoinTool.B!DNS

**OPSEC Guidelines**

 - NA

**An EC2 instance is querying a domain name that is associated with cryptocurrency-related activity.**

**Default severity: High**

This finding informs you that the listed EC2 instance in your AWS environment is querying a domain name that is associated with Bitcoin or other cryptocurrency-related activity. Bitcoin is a worldwide cryptocurrency and digital payment system. Besides being used as a reward for Bitcoin mining, Bitcoin can be exchanged for other currencies, products, and services.

**Remediation recommendations:**

If you use this EC2 instance to mine or manage cryptocurrency, or this instance is otherwise involved in blockchain activity, this finding could represented expected activity for your environment. If this is the case in your AWS environment, we recommend that you set up a suppression rule for this finding. The suppression rule should consist of two filter criteria. The first criteria should use the¬† **Finding type** ¬†attribute with a value of¬†CryptoCurrency:EC2/BitcoinTool.B!DNS. The second filter criteria should be the¬† **Instance ID** ¬†of the instance involved in blockchain activity. To learn more about creating suppression rules see¬†[Suppression rules](https://docs.aws.amazon.com/guardduty/latest/ug/findings_suppression-rule.html).

## Impact:EC2/PortSweep

**OPSEC Guidelines**

- Limit port scanning from a compromised EC2 instance. 

**An EC2 instance is probing a port on a large number of IP addresses.**

**Default severity: High**

This finding informs you the listed EC2 instance in your AWS environment is probing a port on a large number of publicly routable IP addresses. This type of activity is typically used to find vulnerable hosts to exploit.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Impact:EC2/WinRMBruteForce

**OPSEC Guidelines**

- If need to perform a WinRM brute force attack, first move to an internal Windows host so to blend in a little better. Preferably, do not use bruteforcing. 

**An EC2 instance is performing an outbound Windows Remote Management brute force attack.**

**Default severity: High**

This finding informs you that the listed EC2 instance in your AWS environment is performing a Windows Remote Management (WinRM) brute force attack aimed at gaining access to the Windows Remote Management service on Windows-based systems.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Recon:EC2/PortProbeEMRUnprotectedPort

**OPSEC Guidelines**

- NA

**An EC2 instance has an unprotected EMR related port which is being probed by a known malicious host.**

**Default severity: High**

This finding informs you that an EMR related sensitive port on the listed EC2 instance that is part of an cluster in your AWS environment is not blocked by a security group, an access control list (ACL), or an on-host firewall such as Linux IPTables, and that known scanners on the internet are actively probing it. Ports that can trigger this finding, such as port 8088 (YARN Web UI port), could potentially be used for remote code execution.

**Remediation recommendations:**

You should block open access to ports on clusters from the internet and restrict access only to specific IP addresses that require access to these ports. For more information see,¬†[Security Groups for EMR Clusters](https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-security-groups.html).

## Recon:EC2/PortProbeUnprotectedPort

**OPSEC Guidelines**

- NA

**An EC2 instance has an unprotected port that is being probed by a known malicious host.**

**Default severity: Low\***

**Note**

This finding&#39;s default severity is Low. However, if the port being probed is used by (9200 or 9300), the finding&#39;s severity is High.

This finding informs you that a port on the listed EC2 instance in your AWS environment is not blocked by a security group, access control list (ACL), or an on-host firewall such as Linux IPTables, and that known scanners on the internet are actively probing it.

If the identified unprotected port is 22 or 3389 and you are using these ports to connect to your instance, you can still limit exposure by allowing access to these ports only to the IP addresses from your corporate network IP address space. To restrict access to port 22 on Linux, see¬†[Authorizing Inbound Traffic for Your Linux Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html). To restrict access to port 3389 on Windows, see¬†[Authorizing Inbound Traffic for Your Windows Instances](https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/authorizing-access-to-an-instance.html).

**Remediation recommendations:**

There may be cases in which instances are intentionally exposed, for example if they are hosting web servers. If this is the case in your AWS environment, we recommend that you set up a suppression rule for this finding. The suppression rule should consist of two filter criteria. The first criteria should use the¬† **Finding type** ¬†attribute with a value of¬†Recon:EC2/PortProbeUnprotectedPort. The second filter criteria should match the instance or instances that serve as a bastion host. You can use either the¬† **Instance image ID** ¬†attribute or the¬† **Tag** ¬†value attribute, depending on which criteria is identifiable with the instances that host these tools. For more information about creating suppression rules see¬†[Suppression rules](https://docs.aws.amazon.com/guardduty/latest/ug/findings_suppression-rule.html).

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Recon:EC2/Portscan

**OPSEC Guidelines**

- Limit attacking external infrastructure from compromised EC2 instances. 

**An EC2 instance is performing outbound port scans to a remote host.**

**Default severity: Medium**

This finding informs you that the listed EC2 instance in your AWS environment is engaged in a possible port scan attack because it is trying to connect to multiple ports over a short period of time. The purpose of a port scan attack is to locate open ports to discover which services the machine is running and to identify its operating system.

**Remediation recommendations:**

This finding can be a false positive when vulnerability assessment applications are deployed on EC2 instances in your environment because these applications conduct portscans to alert you about misconfigured open ports. If this is the case in your AWS environment, we recommend that you set up a suppression rule for this finding. The suppression rule should consist of two filter criteria. The first criteria should use the¬† **Finding type** ¬†attribute with a value of¬†Recon:EC2/Portscan. The second filter criteria should match the instance or instances that host these vulnerability assessment tools. You can use either the¬† **Instance image ID** ¬†attribute or the¬† **Tag** ¬†value attribute depending on which criteria are identifiable with the instances that host these tools. For more information about creating suppression rules see¬†[Suppression rules](https://docs.aws.amazon.com/guardduty/latest/ug/findings_suppression-rule.html).

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Trojan:EC2/BlackholeTraffic

**OPSEC Guidelines**

- NA

**An EC2 instance is attempting to communicate with an IP address of a remote host that is a known black hole.**

**Default severity: Medium**

This finding informs you the listed EC2 instance in your AWS environment might be compromised because it is trying to communicate with an IP address of a black hole (or sink hole). Black holes are places in the network where incoming or outgoing traffic is silently discarded without informing the source that the data didn&#39;t reach its intended recipient. A black hole IP address specifies a host machine that is not running or an address to which no host has been assigned.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Trojan:EC2/BlackholeTraffic!DNS

**OPSEC Guidelines**

- NA

**An EC2 instance is querying a domain name that is being redirected to a black hole IP address.**

**Default severity: Medium**

This finding informs you the listed EC2 instance in your AWS environment might be compromised because it is querying a domain name that is being redirected to a black hole IP address. Black holes are places in the network where incoming or outgoing traffic is silently discarded without informing the source that the data didn&#39;t reach its intended recipient.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Trojan:EC2/DGADomainRequest.B

**OPSEC Guidelines**

- Use categorized and "readable" domain names for Command and Control traffic.

**An EC2 instance is querying algorithmically generated domains. Such domains are commonly used by malware and could be an indication of a compromised EC2 instance.**

**Default severity: High**

This finding informs you that the listed EC2 instance in your AWS environment is trying to query domain generation algorithm (DGA) domains. Your EC2 instance might be compromised.

DGAs are used to periodically generate a large number of domain names that can be used as rendezvous points with their command and control (C&amp;C) servers. Command and control servers are computers that issue commands to members of a botnet, which is a collection of internet-connected devices that are infected and controlled by a common type of malware. The large number of potential rendezvous points makes it difficult to effectively shut down botnets because infected computers attempt to contact some of these domain names every day to receive updates or commands.

**Note**

This finding is based on analysis of domain names using advanced heuristics and may identify new DGA domains that are not present in threat intelligence feeds.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Trojan:EC2/DGADomainRequest.C!DNS

**OPSEC Guidelines**

- Use categorized and "readable" domain names for Command and Control traffic.

**An EC2 instance is querying algorithmically generated domains. Such domains are commonly used by malware and could be an indication of a compromised EC2 instance.**

**Default severity: High**

This finding informs you that the listed EC2 instance in your AWS environment is trying to query domain generation algorithm (DGA) domains. Your EC2 instance might be compromised.

DGAs are used to periodically generate a large number of domain names that can be used as rendezvous points with their command and control (C&amp;C) servers. Command and control servers are computers that issue commands to members of a botnet, which is a collection of internet-connected devices that are infected and controlled by a common type of malware. The large number of potential rendezvous points makes it difficult to effectively shut down botnets because infected computers attempt to contact some of these domain names every day to receive updates or commands.

**Note**

This finding is based on known DGA domains from GuardDuty&#39;s threat intelligence feeds.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Trojan:EC2/DNSDataExfiltration

**OPSEC Guidelines**

- Keep DNS C2 traffic to a minumum. For example, try not to exfiltrate data over a DNS C2 channel. 

**An EC2 instance is exfiltrating data through DNS queries.**

**Default severity: High**

This finding informs you that the listed EC2 instance in your AWS environment is running malware that uses DNS queries for outbound data transfers. This type of data transfer is indicative of a compromised instance and could result in the exfiltration of data. DNS traffic is not typically blocked by firewalls. For example, malware in a compromised EC2 instance can encode data, (such as your credit card number), into a DNS query and send it to a remote DNS server that is controlled by an attacker.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Trojan:EC2/DriveBySourceTraffic!DNS

**OPSEC Guidelines**

- NA

**An EC2 instance is querying a domain name of a remote host that is a known source of Drive-By download attacks.**

**Default severity: Medium**

This finding informs you that the listed EC2 instance in your AWS environment might be compromised because it is querying a domain name of a remote host that is a known source of drive-by download attacks. These are unintended downloads of computer software from the internet that can trigger an automatic installation of a virus, spyware, or malware.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Trojan:EC2/DropPoint

**OPSEC Guidelines**

- NA

**An EC2 instance is attempting to communicate with an IP address of a remote host that is known to hold credentials and other stolen data captured by malware.**

**Default severity: Medium**

This finding informs you that an EC2 instance in your AWS environment is trying to communicate with an IP address of a remote host that is known to hold credentials and other stolen data captured by malware.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Trojan:EC2/DropPoint!DNS

**OPSEC Guidelines**

- NA

**An EC2 instance is querying a domain name of a remote host that is known to hold credentials and other stolen data captured by malware.**

**Default severity: High**

This finding informs you that an EC2 instance in your AWS environment is querying a domain name of a remote host that is known to hold credentials and other stolen data captured by malware.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## Trojan:EC2/PhishingDomainRequest!DNS

**OPSEC Guidelines**

- NA

**An EC2 instance is querying domains involved in phishing attacks. Your EC2 instance might be compromised.**

**Default severity: High**

This finding informs you that there is an EC2 instance in your AWS environment that is trying to query a domain involved in phishing attacks. Phishing domains are set up by someone posing as a legitimate institution in order to induce individuals to provide sensitive data, such as personally identifiable information, banking and credit card details, and passwords. Your EC2 instance may be trying to retrieve sensitive data stored on a phishing website, or it may be attempting to set up a phishing website. Your EC2 instance might be compromised.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## UnauthorizedAccess:EC2/MaliciousIPCaller.Custom

**OPSEC Guidelines**

- Make sure your phishing infrastrucutre is separated from your C&C infrastructure.

**An EC2 instance is making connections to an IP address on a custom threat list.**

**Default severity: Medium**

This finding informs you that an EC2 instance in your AWS environment is communicating with an IP address included on a threat list that you uploaded. In GuardDuty, a threat list consists of known malicious IP addresses. GuardDuty generates findings based on uploaded threat lists. This can indicate unauthorized access to your AWS resources.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## UnauthorizedAccess:EC2/MetadataDNSRebind

**OPSEC Guidelines**

- Limit queries to the metadata IP. If needed, use the legitimate IP: 169.254.169.254. If attempting to exploit an SSRF, and the metadata IP is blocked, this alert will trigger if you register your own domain name which resolves to the metadata IP. 

**An EC2 instance is performing DNS lookups that resolve to the instance metadata service.**

**Default severity: High**

This finding informs you that an EC2 instance in your AWS environment is querying a domain that resolves to the EC2 metadata IP address (169.254.169.254). A DNS query of this kind may indicate that the instance is a target of a DNS rebinding technique. This technique can be used to obtain metadata from an EC2 instance, including the IAM credentials associated with the instance.

DNS rebinding involves tricking an application running on the EC2 instance to load return data from a URL, where the domain name in the URL resolves to the EC2 metadata IP address (169.254.169.254). This causes the application to access EC2 metadata and possibly make it available to the attacker.

It is possible to access EC2 metadata using DNS rebinding only if the EC2 instance is running a vulnerable application that allows injection of URLs, or if someone accesses the URL in a web browser running on the EC2 instance.

**Remediation recommendations:**

In response to this finding, you should evaluate if there is a vulnerable application running on the EC2 instance, or if someone used a browser to access the domain identified in the finding. If the root cause is a vulnerable application, you should fix the vulnerability. If someone browsed the identified domain, you should block the domain or prevent users from accessing it. If you determine this finding was related to either case above, you should¬†[revoke the session associated with the EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/id_roles_use_revoke-sessions.html).

Some AWS customers intentionally map the metadata IP address to a domain name on their authoritative DNS servers. If this is the case in your environment, we recommend that you set up a suppression rule for this finding. The suppression rule should consist of two filter criteria. The first criteria should use the¬† **Finding type** ¬†attribute with a value of¬†UnauthorizedAccess:EC2/MetaDataDNSRebind. The second filter criteria should be¬† **DNS request domain** ¬†and the value should match the domain you have mapped to the metadata IP address (169.254.169.254). For more information on creating suppression rules see¬†[Suppression rules](https://docs.aws.amazon.com/guardduty/latest/ug/findings_suppression-rule.html).

## UnauthorizedAccess:EC2/RDPBruteForce

**OPSEC Guidelines**

- Do not perform RDP brute forcing from compromised EC2 instances.

**An EC2 instance has been involved in RDP brute force attacks.**

**Default severity: Low\***

**Note**

This finding&#39;s severity is low if your EC2 instance was the target of a brute force attack. This finding&#39;s severity is high if your EC2 instance is the actor being used to perform the brute force attack.

This finding informs you that an EC2 instance in your AWS environment was involved in a brute force attack aimed at obtaining passwords to RDP services on Windows-based systems. This can indicate unauthorized access to your AWS resources.

**Remediation recommendations:**

If your instance&#39;s¬† **Resource Role** ¬†is¬†ACTOR, this indicates your instance has been used to perform RDP brute force attacks. Unless this instance has a legitimate reason to be contacting the IP address listed as the¬†Target, it is recommended that you assume your instance has been compromised and take the actions listed in¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

If your instance&#39;s¬† **Resource Role** ¬†is¬†TARGET, this finding can be remediated by securing your RDP port to only trusted IPs through Security Groups, ACLs, or firewalls. For more information see¬†[Tips for securing your EC2 instances (Linux)](http://aws.amazon.com/articles/tips-for-securing-your-ec2-instance/).

## UnauthorizedAccess:EC2/SSHBruteForce

**OPSEC Guidelines**

- Do not perform SSH brute forcing from EC2 instnaces if possible. 

**An EC2 instance has been involved in SSH brute force attacks.**

**Default severity: Low\***

**Note**

This finding&#39;s severity is low if a brute force attack is aimed at one of your EC2 instances. This finding&#39;s severity is high if your EC2 instance is being used to perform the brute force attack.

This finding informs you that an EC2 instance in your AWS environment was involved in a brute force attack aimed at obtaining passwords to SSH services on Linux-based systems. This can indicate unauthorized access to your AWS resources.

**Note**

This finding is generated only through monitoring traffic on port 22. If your SSH services are configured to use other ports, this finding is not generated.

**Remediation recommendations:**

If the target of the brute force attempt is a bastion host, this may represent expected behavior for your AWS environment. If this is the case, we recommend that you set up a suppression rule for this finding. The suppression rule should consist of two filter criteria. The first criteria should use the¬† **Finding type** ¬†attribute with a value of¬†UnauthorizedAccess:EC2/SSHBruteForce. The second filter criteria should match the instance or instances that serve as a bastion host. You can use either the¬† **Instance image ID** ¬†attribute or the¬† **Tag** ¬†value attribute depending on which criteria is identifiable with the instances that host these tools. For more information about creating suppression rules see¬†[Suppression rules](https://docs.aws.amazon.com/guardduty/latest/ug/findings_suppression-rule.html).

If this activity is not expected for your environment and your instance&#39;s¬† **Resource Role** ¬†is¬†TARGET, this finding can be remediated by securing your SSH port to only trusted IPs through Security Groups, ACLs, or firewalls. For more information, see¬†[Tips for securing your EC2 instances (Linux)](http://aws.amazon.com/articles/tips-for-securing-your-ec2-instance/).

If your instance&#39;s¬† **Resource Role** ¬†is¬†ACTOR, this indicates the instance has been used to perform SSH brute force attacks. Unless this instance has a legitimate reason to be contacting the IP address listed as the¬†Target, it is recommended that you assume your instance has been compromised and take the actions listed in¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## UnauthorizedAccess:EC2/TorClient

**OPSEC Guidelines**

- NA

**Your EC2 instance is making connections to a Tor Guard or an Authority node.**

**Default severity: High**

This finding informs you that an EC2 instance in your AWS environment is making connections to a Tor Guard or an Authority node. Tor is software for enabling anonymous communication. Tor Guards and Authority nodes act as initial gateways into a Tor network. This traffic can indicate that this EC2 instance has been compromised and is acting as a client on a Tor network. This finding may indicate unauthorized access to your AWS resources with the intent of hiding the attacker&#39;s true identity.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

## UnauthorizedAccess:EC2/TorRelay

**OPSEC Guidelines**

- NA

**Your EC2 instance is making connections to a Tor network as a Tor relay.**

**Default severity: High**

This finding informs you that an EC2 instance in your AWS environment is making connections to a Tor network in a manner that suggests that it&#39;s acting as a Tor relay. Tor is software for enabling anonymous communication. Tor increases anonymity of communication by forwarding the client&#39;s possibly illicit traffic from one Tor relay to another.

**Remediation recommendations:**

If this activity is unexpected, your instance is likely compromised, see¬†[Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2).

# IAM Findings

## PenTest:IAMUser/KaliLinux

**An API was invoked from a Kali Linux EC2 machine.**

**OPSEC Guidelines**

- Do not use the default Kali Linux user agents. 

**Default severity: Medium**

This finding informs you that a machine running Kali Linux is making API calls using credentials that belong to the listed AWS account in your environment. Kali Linux is a popular penetration testing tool that security professionals use to identify weaknesses in EC2 instances that require patching. Attackers also use this tool to find EC2 configuration weaknesses and gain unauthorized access to your AWS environment.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## PenTest:IAMUser/ParrotLinux

**OPSEC Guidelines**

- Do not use the default Parrot Linux user agents.

**An API was invoked from a Parrot Security Linux machine.**

**Default severity: Medium**

This finding informs you that a machine running Parrot Security Linux is making API calls using credentials that belong to the listed AWS account in your environment. Parrot Security Linux is a popular penetration testing tool that security professionals use to identify weaknesses in EC2 instances that require patching. Attackers also use this tool to find EC2 configuration weaknesses and gain unauthorized access to your AWS environment.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## PenTest:IAMUser/PentooLinux

**OPSEC Guidelines**

- Do not use the default Pentoo Linux user agents.

**An API was invoked from a Pentoo Linux machine.**

**Default severity: Medium**

This finding informs you that a machine running Pentoo Linux is making API calls using credentials that belong to the listed AWS account in your environment. Pentoo Linux is a popular penetration testing tool that security professionals use to identify weaknesses in EC2 instances that require patching. Attackers also use this tool to find EC2 configuration weaknesses and gain unauthorized access to your AWS environment.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Persistence:IAMUser/NetworkPermissions

**OPSEC Guidelines**

- Make sure when calling AWS API's using compromised credentals, the credentials fit the action. 

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

- Make sure when calling AWS API's using compromised credentals, the credentials fit the action. 

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

- Make sure when calling AWS API's using compromised credentals, the credentials fit the action. 

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

- Do not use Root credentials if possible. If you must, perform actions that the Root account has performed in the past. 

**An API was invoked using root credentials.**

**Default severity: Low**

This finding informs you that the root credentials of the listed AWS account in your environment are being used to make requests to AWS services. It is recommended that users never use root credentials to access AWS services. Instead, AWS services should be accessed using least privilege temporary credentials from AWS Security Token Service (STS). For situations where STS is not supported, IAM user credentials are recommended. For more information, see¬†[IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

**Note**

If S3 threat detection is enabled for the account this finding may be generated in response to attempts to run S3 data plane operations on S3 resources using the root credentials of the AWS account. The API call used will be listed in the finding details. If S3 threat detection is not enabled this finding can only be triggered by Event log API&#39;s. For more information on S3 threat detection see¬†[Amazon S3 protection in Amazon GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/s3_detection.html).

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## PrivilegeEscalation:IAMUser/AdministrativePermissions

**OPSEC Guidelines**

- Before performing actions in AWS, confirm current roles and permissions. Make sure actions being attempted are allowed under the current policies.

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

- Make sure your infrastructure abides by role seperation. Use different infrastrucutre, or at least different egress IP's for different stages.

**An API was invoked from a known malicious IP address.**

**Default severity: Medium**

This finding informs you that an API operation that can list or describe AWS resources in an account within your environment was invoked from an IP address that is included on an internal threat list. generates findings based off of third-party partner threat lists. The threat list used to generate this finding will be listed in the finding&#39;s details. An attacker might use stolen credentials to perform this type of reconnaissance of your AWS resources in order to find more valuable credentials or determine the capabilities of the credentials they already have.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Recon:IAMUser/MaliciousIPCaller.Custom

**OPSEC Guidelines**

- Make sure your infrastructure abides by role seperation. Use different infrastrucutre, or at least different egress IP's for different stages.

**An API was invoked from a known malicious IP address.**

**Default severity: Medium**

This finding informs you that an API operation that can list or describe AWS resources in an account within your environment was invoked from an IP address that is included on a custom threat list. The threat list used will be listed in the finding&#39;s details. An attacker might use stolen credentials to perform this type of reconnaissance of your AWS resources in order to find more valuable credentials or determine the capabilities of the credentials they already have.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Recon:IAMUser/NetworkPermissions

**OPSEC Guidelines**

- Make sure when calling AWS API's using compromised credentals, the credentials fit the action. 

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

- Make sure when calling AWS API's using compromised credentals, the credentials fit the action. 

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

- NA

**An API was invoked from a Tor exit node IP address.**

**Default severity: Medium**

This finding informs you that an API operation that can list or describe AWS resources in an account within your environment was invoked from a Tor exit node IP address. Tor is software for enabling anonymous communication. It encrypts and randomly bounces communications through relays between a series of network nodes. The last Tor node is called the exit node. An attacker would use Tor to mask their true identity.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Recon:IAMUser/UserPermissions

**OPSEC Guidelines**

- Make sure when calling AWS API's using compromised credentals, the credentials fit the action. 

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

- Make sure when calling AWS API's using compromised credentals, the credentials fit the action. 

**A principal invoked an API commonly used to launch Compute resources like EC2 Instances.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding is triggered when EC2 instances in the listed account within your AWS environment are launched under suspicious circumstances. This finding indicates that a specific principal in your AWS environment is exhibiting behavior that is different from the established baseline; for example, if a principal (AWS account root user, IAM role, or IAM user) invoked the¬†RunInstances¬†API with no prior history of doing so. This might be an indication of an attacker using stolen credentials to steal compute time (possibly for cryptocurrency mining or password cracking). It can also be an indication of an attacker using an EC2 instance in your AWS environment and its credentials to maintain access to your account.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Stealth:IAMUser/CloudTrailLoggingDisabled

**OPSEC Guidelines**

- Do not disable the CloudTrail log if possible. If needed, after malicous actions are complete, delete the S3 bucket that stores the log. This will still trigger this alarm, but that malicous actions will be complete already. 

**AWS CloudTrail trail was disabled.**

**Default severity: Low**

This finding informs you that a CloudTrail trail within your AWS environment was disabled. This can be an attacker&#39;s attempt to disable logging to cover their tracks by eliminating any trace of their activity while gaining access to your AWS resources for malicious purposes. This finding can be triggered by a successful deletion or update of a trail. This finding can also be triggered by a successful deletion of an S3 bucket that stores the logs from a trail that is associated with GuardDuty.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Stealth:IAMUser/LoggingConfigurationModified

**OPSEC Guidelines**

- Do not disable the CloudTrail log if possible. If needed, after malicous actions are complete, delete the S3 bucket that stores the log. This will still trigger this alarm, but that malicous actions will be complete already.  

**A principal invoked an API commonly used to stop CloudTrail Logging, delete existing logs, and otherwise eliminate traces of activity in your AWS account.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding is triggered when the logging configuration in the listed AWS account within your environment is modified under suspicious circumstances. This finding informs you that a specific principal in your AWS environment is exhibiting behavior that is different from the established baseline; for example, if a principal (AWS account root user, IAM role, or IAM user) invoked the¬†StopLogging¬†API with no prior history of doing so. This can be an indication of an attacker trying to cover their tracks by eliminating any trace of their activity.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## Stealth:IAMUser/PasswordPolicyChange

**OPSEC Guidelines**

- Try not to weaken the security of your target. 

**Account password policy was weakened.**

**Default severity: Low**

The AWS account password policy was weakened on the listed account within your AWS environment. For example, it was deleted or updated to require fewer characters, not require symbols and numbers, or required to extend the password expiration period. This finding can also be triggered by an attempt to update or delete your AWS account password policy. The AWS account password policy defines the rules that govern what kinds of passwords can be set for your IAM users. A weaker password policy permits the creation of passwords that are easy to remember and potentially easier to guess, thereby creating a security risk.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## UnauthorizedAccess:IAMUser/ConsoleLogin

**OPSEC Guidelines**

- If at all possible, work from the AWS CLI. Unless victim does not work from CLI typically. 
- Do not create console logins for temporary AWS credentials stolen from an EC2 instance.

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

- If using stolen credentials, use a VPN from a similar location as your victim.
- Pivot through victim if possible. 

**Multiple worldwide successful console logins were observed.**

**Default severity: Medium**

This finding informs you that multiple successful console logins for the same IAM user were observed around the same time in various geographical locations. Such anomalous and risky access location patterns indicate potential unauthorized access to your AWS resources.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration

**OPSEC Guidelines**

- If using stolen AWS EC2 credentials, use them from an EC2 instance. 

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

- NA

**An API was invoked from a known malicious IP address.**

**Default severity: Medium**

This finding informs you that an API operation (for example, an attempt to launch an EC2 instance, create a new IAM user, modify your AWS privileges) was invoked from a known malicious IP address. This can indicate unauthorized access to AWS resources within your environment.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom

**OPSEC Guidelines**

- Make sure your infrastructure abides by role seperation. Use different infrastrucutre, or at least different egress IP's for different stages.

**An API was invoked from an IP address on a custom threat list.**

**Default severity: Medium**

This finding informs you that an API operation (for example, an attempt to launch an EC2 instance, create a new IAM user, modify AWS privileges) was invoked from an IP address that is included on a threat list that you uploaded. In , a threat list consists of known malicious IP addresses. generates findings based on uploaded threat lists. This can indicate unauthorized access to your AWS resources within your environment.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

## UnauthorizedAccess:IAMUser/TorIPCaller

**OPSEC Guidelines**

- NA

**An API was invoked from a Tor exit node IP address.**

**Default severity: Medium**

This finding informs you that an API operation (for example, an attempt to launch an EC2 instance, create a new IAM user, or modify your AWS privileges) was invoked from a Tor exit node IP address. Tor is software for enabling anonymous communication. It encrypts and randomly bounces communications through relays between a series of network nodes. The last Tor node is called the exit node. This can indicate unauthorized access to your AWS resources with the intent of hiding the attacker&#39;s true identity.

**Remediation recommendations:**

If this activity is unexpected your credentials may be compromised, see¬†[Remediating compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds).

# S3 Findings

## Discovery:S3/BucketEnumeration.Unusual

**An IAM entity invoked an S3 API used to discover S3 buckets within your network.**

**OPSEC Guidance**

- Make sure if you're calling list buckets, or similar API calls, you are using a AWS user that would call these. In many cases, an AWS user would probably call this, but an EC2 instance session user might not.

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding informs you that an IAM entity has invoked an S3 API to discover S3 buckets in your environment, such as¬†ListBuckets. This type of activity is associated with the discovery stage of an attack wherein an attacker is gathering information to determine if your AWS environment is susceptible to a broader attack. This activity is suspicious because the way the IAM entity invoked the API was unusual. For example, this IAM entity had no prior history of invoking this type of API, or the API was invoked from an unusual location.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## Discovery:S3/MaliciousIPCaller.Custom

**OPSEC Guidance**

- Make sure your infrastructure abides by role seperation. Use different infrastrucutre, or at least different egress IP's for different stages.

**An S3 API was invoked from an IP address on a custom threat list.**

**Default severity: High**

This finding informs you that an S3 API, such as¬†GetObjectAcl¬†or¬†ListObjects, was invoked from an IP address that is included on a threat list that you uploaded. The threat list associated with this finding is listed in the¬† **Additional information** ¬†section of a finding&#39;s details. This type of activity is associated with the discovery stage of an attack wherein an attacker is gathering information to determine if your AWS environment is susceptible to a broader attack.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## Discovery:S3/TorIPCaller

**OPSEC Guidance**

- NA

**An S3 API was invoked from a Tor exit node IP address.**

**Default severity: Medium**

This finding informs you that an S3 API, such as¬†GetObjectAcl¬†or¬†ListObjects, was invoked from a Tor exit node IP address. This type of activity is associated with the discovery stage of an attack wherein an attacker is gathering information to determine if your AWS environment is susceptible to a broader attack. Tor is software for enabling anonymous communication. It encrypts and randomly bounces communications through relays between a series of network nodes. The last Tor node is called the exit node. This can indicate unauthorized access to your AWS resources with the intent of hiding the attacker&#39;s true identity.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## Exfiltration:S3/ObjectRead.Unusual

**OPSEC Guidance**

- Make sure when calling AWS API's using compromised credentals, the credentials fit the action.

**An IAM entity invoked an S3 API in a suspicious way.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding informs you that a IAM entity in your AWS environment is making API calls that involve an S3 bucket and that differ from that entity&#39;s established baseline. The API call used in this activity is associated with the exfiltration stage of an attack, wherein and attacker is attempting to collect data. This activity is suspicious because the way the IAM entity invoked the API was unusual. For example, this IAM entity had no prior history of invoking this type of API, or the API was invoked from an unusual location.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## Impact:S3/PermissionsModification.Unusual

**OPSEC Guidance**

- If possible, do not modify the target environment. In this case, do not modify the permissions of an S3 bucket. If access is needed to a bucket, and the current user can modify bucket permissions, but not access the data in the bucket, attempt to obtain credentials to a user that can access the bucket. 
- Do not use temporary AWS credentials that were created on an instance.

**An IAM entity invoked an API to modify permissions on one or more S3 resources.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding informs you that an IAM entity is making API calls designed to modify the permissions on one or more buckets or objects in your AWS environment. This action may be performed by an attacker to allow information to be shared outside of the account. This activity is suspicious because the way the IAM entity invoked the API was unusual. For example, this IAM entity had no prior history of invoking this type of API, or the API was invoked from an unusual location.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## Impact:S3/ObjectDelete.Unusual

**OPSEC Guidance**

- Make sure when calling AWS API's using compromised credentals, the credentials fit the action.
- Do not use temporary AWS credentials that were created on an instance.

**An IAM entity invoked an API used to delete data in an S3 bucket.**

**Default severity: Medium\***

**Note**

This finding&#39;s default severity is Medium. However, if the API is invoked using temporary AWS credentials that are created on an instance, the finding&#39;s severity is High.

This finding informs you that a specific IAM entity in your AWS environment is making API calls designed to delete data in the listed S3 bucket by deleting the bucket itself. This activity is suspicious because the way the IAM entity invoked the API was unusual. For example, this IAM entity had no prior history of invoking this type of API, or the API was invoked from an unusual location.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## PenTest:S3/KaliLinux

**OPSEC Guidance**

- Do not use the default Kali Linux user agents.

**An S3 API was invoked from a Kali Linux machine.**

**Default severity: Medium**

This finding informs you that a machine running Kali Linux is making S3 API calls using credentials that belong to your AWS account. Your credentials might be compromised. Kali Linux is a popular penetration testing tool that security professionals use to identify weaknesses in EC2 instances that require patching. Attackers also use this tool to find EC2 configuration weaknesses and gain unauthorized access to your AWS environment.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## PenTest:S3/ParrotLinux

**OPSEC Guidance**

- Do not use the default Parrot Linux user agents.

**An S3 API was invoked from a Parrot Security Linux machine.**

**Default severity: Medium**

This finding informs you that a machine running Parrot Security Linux is making S3 API calls using credentials that belong to your AWS account. Your credentials might be compromised. Parrot Security Linux is a popular penetration testing tool that security professionals use to identify weaknesses in EC2 instances that require patching. Attackers also use this tool to find EC2 configuration weaknesses and gain unauthorized access to your AWS environment.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## PenTest:S3/PentooLinux

**OPSEC Guidance**

- Do not use the default Pentoo Linux user agents.

**An S3 API was invoked from a Pentoo Linux machine**

**Default severity: Medium**

This finding informs you that a machine running Pentoo Linux is making S3 API calls using credentials that belong to your AWS account. Your credentials might be compromised. Pentoo Linux is a popular penetration testing tool that security professionals use to identify weaknesses in EC2 instances that require patching. Attackers also use this tool to find EC2 configuration weaknesses and gain unauthorized access to your AWS environment.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## Policy:S3/AccountBlockPublicAccessDisabled

**OPSEC Guidance**

- There few scenarios when data from a victim should be exposed to the public. Exfiltrate data by first pulling the data down internally, and then exfiltrating data from there. 

**An IAM entity invoked an API used to disable S3 block public access on an account.**

**Default severity: Low**

This finding informs you that Amazon S3 Block Public Access was disabled at the account level. When S3 Block Public Access settings are enabled, they are used to filter the policies or access control lists (ACLs) on buckets as a security measure to prevent inadvertent public exposure of data.

Typically, S3 Block Public Access is turned off in an account to allow public access to a bucket or to the objects in the bucket. When S3 Block Public Access is disabled for an account, access to your buckets is controlled by the policies, ACLs, or bucket-level Block Public Access settings applied to your individual buckets. This does not necessarily mean that the buckets are shared publicly, but that you should audit the permissions applied to the buckets to confirm that they provide the appropriate level of access.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## Policy:S3/BucketBlockPublicAccessDisabled

**OPSEC Guidance**

- There few scenarios when data from a victim should be exposed to the public. Exfiltrate data by first pulling the data down internally, and then exfiltrating data from there. 

**An IAM entity invoked an API used to disable S3 block public access on a bucket.**

**Default severity: Low**

This finding informs you that Block Public Access was disabled for the listed S3 bucket. When enabled, S3 Block Public Access settings are used to filter the policies or access control lists (ACLs) applied to buckets as a security measure to prevent inadvertent public exposure of data.

Typically, S3 Block Public Access is turned off on a bucket to allow public access to the bucket or to the objects within. When S3 Block Public Access is disabled for a bucket, access to the bucket is controlled by the policies or ACLs applied to it. This does not mean that the bucket is shared publicly, but you should audit the policies and ACLs applied to the bucket to confirm that appropriate permissions are applied.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## Policy:S3/BucketAnonymousAccessGranted

**OPSEC Guidance**

- There few scenarios when data from a victim should be exposed to the public. Exfiltrate data by first pulling the data down internally, and then exfiltrating data from there. 

**An IAM principal has granted access to an S3 bucket to the internet by changing bucket policies or ACLs.**

**Default severity: High**

This finding informs you that the listed S3 bucket has been made publicly accessible on the internet because an IAM entity has changed a bucket policy or ACL on that bucket. After a policy or ACL change is detected, uses automated reasoning powered by¬†[Zelkova](https://aws.amazon.com/blogs/security/protect-sensitive-data-in-the-cloud-with-automated-reasoning-zelkova/), to determine if the bucket is publicly accessible.

**Note**

If a bucket&#39;s ACLs or bucket policies are configured to explicitly deny or to deny all, this finding cannot be generated for that bucket.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## Policy:S3/BucketPublicAccessGranted

**OPSEC Guidance**

- There few scenarios when data from a victim should be exposed to the public. Exfiltrate data by first pulling the data down internally, and then exfiltrating data from there. 

**An IAM principal has granted public access to an S3 bucket to all AWS users by changing bucket policies or ACLs.**

**Default severity: High**

This finding informs you that the listed S3 bucket has been publicly exposed to all authenticated AWS users because an IAM entity has changed a bucket policy or ACL on that S3 bucket. After a policy or ACL change is detected, uses automated reasoning powered by¬†[Zelkova](https://aws.amazon.com/blogs/security/protect-sensitive-data-in-the-cloud-with-automated-reasoning-zelkova/), to determine if the bucket is publicly accessible.

**Note**

If a bucket&#39;s ACLs or bucket policies are configured to explicitly deny or to deny all, this finding cannot be generated for that bucket.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## Stealth:S3/ServerAccessLoggingDisabled

**OPSEC Guidance**

- Attempt to use an AWS account that should be reading data from S3. This way, server access logs indicating data access by the compromised account do not raise an suspicion.  


**S3 server access logging was disabled for a bucket.**

**Default severity: Low**

This finding informs you that S3 server access logging is disabled for a bucket within your AWS environment. If disabled, no logs are created for any actions taken on the identified S3 bucket or on the objects in the bucket, unless S3 object level logging is enabled for this bucket. Disabling logging is a technique used by unauthorized users in order to cover their tracks. This finding is triggered when server access logging is disabled for a bucket. To learn more, see¬†[S3 Server Access Logging](https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html).

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## UnauthorizedAccess:S3/MaliciousIPCaller.Custom

**OPSEC Guidance**

- Make sure your infrastructure abides by role seperation. Use different infrastrucutre, or at least different egress IP's for different stages.

**An S3 API was invoked from an IP address on a custom threat list.**

**Default severity: High**

This finding informs you that an S3 API operation, for example,¬†PutObject¬†or¬†PutObjectAcl, was invoked from an IP address that is included on a threat list that you uploaded. The threat list associated with this finding is listed in the¬† **Additional information** ¬†section of a finding&#39;s details.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).

## UnauthorizedAccess:S3/TorIPCaller

**OPSEC Guidance**

- NA

**An S3 API was invoked from a Tor exit node IP address.**

**Default severity: High**

This finding informs you that an S3 API operation, such as¬†PutObject¬†or¬†PutObjectAcl, was invoked from a Tor exit node IP address. Tor is software for enabling anonymous communication. It encrypts and randomly bounces communications through relays between a series of network nodes. The last Tor node is called the exit node. This finding can indicate unauthorized access to your AWS resources with the intent of hiding the attacker&#39;s true identity.

**Remediation recommendations:**

If this activity is unexpected for the associated principal it may indicate the credentials have been exposed or your S3 permissions are not restrictive enough, see¬†[Remediating a Compromised S3 Bucket](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-s3).
