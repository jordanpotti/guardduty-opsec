# guardduty-opsec

Guardduty is AWS's security monitoring service that analyzes VPC Flow Logs, AWS CloudTrail management event logs, Cloudtrail S3 event logs and DNS logs. Typically, its the lowest bar for monitoring in an AWS environment, but can and does trip up attackers, pentesters and red teams. 


| FINDING TYPE      | THREAT PURPOSE | RESOURCE | SEVERITY | OPSEC GUIDANCE | 
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | -------- | -------- | -------- |
| [Backdoor:EC2/C&CActivity.B!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-ccactivitybdns)  | Backdoor | EC2 | High |
| [Backdoor:EC2/DenialOfService.Dns](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofservicedns)  | Backdoor | EC2 | High |
| [Backdoor:EC2/DenialOfService.Tcp](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofservicetcp)  | Backdoor | EC2 | High |
| [Backdoor:EC2/DenialOfService.Udp](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofserviceudp)  | Backdoor | EC2 | High |
| [Backdoor:EC2/DenialOfService.UdpOnTcpPorts](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofserviceudpontcpports) | Backdoor | EC2 | High |
| [Backdoor:EC2/DenialOfService.UnusualProtocol](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-denialofserviceunusualprotocol) | Backdoor | EC2 | High |
| [Backdoor:EC2/Spambot](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#backdoor-ec2-spambot)   | Backdoor | EC2 | Medium |
| [Behavior:EC2/NetworkPortUnusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#behavior-ec2-networkportunusual)  | Behavior | EC2 | Medium |
| [Behavior:EC2/TrafficVolumeUnusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#behavior-ec2-trafficvolumeunusual)  | Behavior | EC2 | Medium |
| [CryptoCurrency:EC2/BitcoinTool.B](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#cryptocurrency-ec2-bitcointoolb)  | CryptoCurrency | EC2 | High |
| [CryptoCurrency:EC2/BitcoinTool.B!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#cryptocurrency-ec2-bitcointoolbdns)  | CryptoCurrency | EC2 | High |
| [Impact:EC2/WinRMBruteForce](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#impact-ec2-winrmbruteforce)  | Impact | EC2 | High |
| [Impact:EC2/PortSweep](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#impact-ec2-portsweep)   | Impact | EC2 | High |
| [Recon:EC2/PortProbeEMRUnprotectedPort](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portprobeemrunprotectedport)  | Recon | EC2 | High |
| [Recon:EC2/PortProbeUnprotectedPort](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portprobeunprotectedport)  | Recon | EC2 | Low\* |
| [Recon:EC2/Portscan](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#recon-ec2-portscan)   | Recon | EC2 | Medium |
| [Trojan:EC2/BlackholeTraffic](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-blackholetraffic)  | Trojan | EC2 | Medium |
| [Trojan:EC2/BlackholeTraffic!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-blackholetrafficdns)  | Trojan | EC2 | Medium |
| [Trojan:EC2/DGADomainRequest.B](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-dgadomainrequestb)  | Trojan | EC2 | High |
| [Trojan:EC2/DGADomainRequest.C!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-dgadomainrequestcdns)  | Trojan | EC2 | High |
| [Trojan:EC2/DNSDataExfiltration](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-dnsdataexfiltration)  | Trojan | EC2 | High |
| [Trojan:EC2/DriveBySourceTraffic!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-drivebysourcetrafficdns)  | Trojan | EC2 | Medium |
| [Trojan:EC2/DropPoint](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-droppoint)   | Trojan | EC2 | Medium |
| [Trojan:EC2/DropPoint!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-droppointdns)  | Trojan | EC2 | High |
| [Trojan:EC2/PhishingDomainRequest!DNS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#trojan-ec2-phishingdomainrequestdns)  | Trojan | EC2 | High |
| [UnauthorizedAccess:EC2/MaliciousIPCaller.Custom](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-maliciousipcallercustom) | UnauthorizedAccess | EC2 | Medium |
| [UnauthorizedAccess:EC2/MetadataDNSRebind](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-metadatadnsrebind) | UnauthorizedAccess | EC2 | High |
| [UnauthorizedAccess:EC2/RDPBruteForce](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-rdpbruteforce)  | UnauthorizedAccess | EC2 | Low\* |
| [UnauthorizedAccess:EC2/SSHBruteForce](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-sshbruteforce)  | UnauthorizedAccess | EC2 | Low\* |
| [UnauthorizedAccess:EC2/TorClient](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-torclient)  | UnauthorizedAccess | EC2 | High |
| [UnauthorizedAccess:EC2/TorRelay](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-torrelay)  | UnauthorizedAccess | EC2 | High |
| [PenTest:IAMUser/KaliLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-kalilinux)   | PenTest | IAM | Medium |
| [PenTest:IAMUser/ParrotLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-parrotlinux)  | PenTest | IAM | Medium |
| [PenTest:IAMUser/PentooLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-pentoolinux)  | PenTest | IAM | Medium |
| [Persistence:IAMUser/NetworkPermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#persistence-iam-networkpermissions)  | Persistence | IAM | Medium\* |
| [Persistence:IAMUser/ResourcePermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#persistence-iam-resourcepermissions)  | Persistence | IAM | Medium\* |
| [Persistence:IAMUser/UserPermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#persistence-iam-userpermissions)  | Persistence | IAM | Medium\* |
| [Policy:IAMUser/RootCredentialUsage](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#policy-iam-rootcredentialusage)  | Policy | IAM | Low |
| [PrivilegeEscalation:IAMUser/AdministrativePermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#privilegeescalation-iam-administrativepermissions) | PrivilegeEscalation | IAM | Low\* |
| [Recon:IAMUser/MaliciousIPCaller](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-maliciousipcaller)  | Recon | IAM | Medium |
| [Recon:IAMUser/MaliciousIPCaller.Custom](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-maliciousipcallercustom)  | Recon | IAM | Medium |
| [Recon:IAMUser/NetworkPermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-networkpermissions)  | Recon | IAM | Medium\* |
| [Recon:IAMUser/ResourcePermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-resourcepermissions)  | Recon | IAM | Medium\* |
| [Recon:IAMUser/TorIPCaller](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-toripcaller)   | Recon | IAM | Medium |
| [Recon:IAMUser/UserPermissions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-userpermissions)  | Recon | IAM | Medium\* |
| [ResourceConsumption:IAMUser/ComputeResources](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#resourceconsumption-iam-computeresources) | ResourceConsumption | IAM | Medium\* |
| [Stealth:IAMUser/CloudTrailLoggingDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-cloudtrailloggingdisabled)  | Stealth | IAM | Low |
| [Stealth:IAMUser/LoggingConfigurationModified](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-loggingconfigurationmodified) | Stealth | IAM | Medium\* |
| [Stealth:IAMUser/PasswordPolicyChange](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-passwordpolicychange)  | Stealth | IAM | Low |
| [UnauthorizedAccess:IAMUser/ConsoleLogin](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-consolelogin)  | UnauthorizedAccess | IAM | Medium\* |
| [UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-consoleloginsuccessb) | UnauthorizedAccess | IAM | Medium |
| [UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-instancecredentialexfiltration) | UnauthorizedAccess | IAM | High |
| [UnauthorizedAccess:IAMUser/MaliciousIPCaller](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-maliciousipcaller) | UnauthorizedAccess | IAM | Medium |
| [UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-maliciousipcallercustom) | UnauthorizedAccess | IAM | Medium |
| [UnauthorizedAccess:IAMUser/TorIPCaller](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-toripcaller)  | UnauthorizedAccess | IAM | Medium |
| [Discovery:S3/BucketEnumeration.Unusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-bucketenumerationunusual)  | Discovery | S3 | Medium |
| [Discovery:S3/MaliciousIPCaller.Custom](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-maliciousipcallercustom)  | Discovery | S3 | High |
| [Discovery:S3/TorIPCaller](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-toripcaller)  | Discovery | S3 | Medium |
| [Exfiltration:S3/ObjectRead.Unusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#exfiltration-s3-objectreadunusual)  | Exfiltration | S3 | Medium |
| [Impact:S3/PermissionsModification.Unusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#impact-s3-permissionsmodificationunusual) | Impact | S3 | Medium |
| [Impact:S3/ObjectDelete.Unusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#impact-s3-objectdeleteunusual)  | Impact | S3 | Medium |
| [PenTest:S3/KaliLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#pentest-s3-kalilinux)   | PenTest | S3 | Medium |
| [PenTest:S3/ParrotLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#pentest-s3-parrotlinux)   | PenTest | S3 | Medium |
| [PenTest:S3/PentooLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#pentest-s3-pentoolinux)   | PenTest | S3 | Medium |
| [Policy:S3/AccountBlockPublicAccessDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-accountblockpublicaccessdisabled) | Policy | S3 | Low |
| [Policy:S3/BucketBlockPublicAccessDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketblockpublicaccessdisabled) | Policy | S3 | Low |
| [Policy:S3/BucketAnonymousAccessGranted](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketanonymousaccessgranted)  | Policy | S3 | High |
| [Policy:S3/BucketPublicAccessGranted](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketpublicaccessgranted)  | Policy | S3 | High |
| [Stealth:S3/ServerAccessLoggingDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#stealth-s3-serveraccessloggingdisabled)  | Stealth | S3 | Low |
| [UnauthorizedAccess:S3/MaliciousIPCaller.Custom](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#unauthorizedaccess-s3-maliciousipcallercustom) | UnauthorizedAccess | S3 | High |
| [UnauthorizedAccess:S3/TorIPCaller](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#unauthorizedaccess-s3-toripcaller)  | UnauthorizedAccess | S3 | High |
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
