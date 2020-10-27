# guardduty-opsec

Guardduty is AWS's security monitoring service that analyzes VPC Flow Logs, AWS CloudTrail management event logs, Cloudtrail S3 event logs and DNS logs. Typically, its the lowest bar for monitoring in an AWS environment, but can and does trip up attackers, pentesters and red teams. 



| FINDING TYPE                                              | THREAT PURPOSE      | RESOURCE | SEVERITY | BYPASS |
|-----------------------------------------------------------|---------------------|----------|----------|--------|
| Backdoor:EC2/C&CActivity.B!DNS                            | Backdoor            | EC2      | High     |
| Backdoor:EC2/DenialOfService.Dns                          | Backdoor            | EC2      | High     |
| Backdoor:EC2/DenialOfService.Tcp                          | Backdoor            | EC2      | High     |
| Backdoor:EC2/DenialOfService.Udp                          | Backdoor            | EC2      | High     |
| Backdoor:EC2/DenialOfService.UdpOnTcpPorts                | Backdoor            | EC2      | High     |
| Backdoor:EC2/DenialOfService.UnusualProtocol              | Backdoor            | EC2      | High     |
| Backdoor:EC2/Spambot                                      | Backdoor            | EC2      | Medium   |
| Behavior:EC2/NetworkPortUnusual                           | Behavior            | EC2      | Medium   |
| Behavior:EC2/TrafficVolumeUnusual                         | Behavior            | EC2      | Medium   |
| CryptoCurrency:EC2/BitcoinTool.B                          | CryptoCurrency      | EC2      | High     |
| CryptoCurrency:EC2/BitcoinTool.B!DNS                      | CryptoCurrency      | EC2      | High     |
| Impact:EC2/WinRMBruteForce                                | Impact              | EC2      | High     |
| Impact:EC2/PortSweep                                      | Impact              | EC2      | High     |
| Recon:EC2/PortProbeEMRUnprotectedPort                     | Recon               | EC2      | High     |
| Recon:EC2/PortProbeUnprotectedPort                        | Recon               | EC2      | Low*     |
| Recon:EC2/Portscan                                        | Recon               | EC2      | Medium   |
| Trojan:EC2/BlackholeTraffic                               | Trojan              | EC2      | Medium   |
| Trojan:EC2/BlackholeTraffic!DNS                           | Trojan              | EC2      | Medium   |
| Trojan:EC2/DGADomainRequest.B                             | Trojan              | EC2      | High     |
| Trojan:EC2/DGADomainRequest.C!DNS                         | Trojan              | EC2      | High     |
| Trojan:EC2/DNSDataExfiltration                            | Trojan              | EC2      | High     |
| Trojan:EC2/DriveBySourceTraffic!DNS                       | Trojan              | EC2      | Medium   |
| Trojan:EC2/DropPoint                                      | Trojan              | EC2      | Medium   |
| Trojan:EC2/DropPoint!DNS                                  | Trojan              | EC2      | High     |
| Trojan:EC2/PhishingDomainRequest!DNS                      | Trojan              | EC2      | High     |
| UnauthorizedAccess:EC2/MaliciousIPCaller.Custom           | UnauthorizedAccess  | EC2      | Medium   |
| UnauthorizedAccess:EC2/MetadataDNSRebind                  | UnauthorizedAccess  | EC2      | High     |
| UnauthorizedAccess:EC2/RDPBruteForce                      | UnauthorizedAccess  | EC2      | Low*     |
| UnauthorizedAccess:EC2/SSHBruteForce                      | UnauthorizedAccess  | EC2      | Low*     |
| UnauthorizedAccess:EC2/TorClient                          | UnauthorizedAccess  | EC2      | High     |
| UnauthorizedAccess:EC2/TorRelay                           | UnauthorizedAccess  | EC2      | High     |
| PenTest:IAMUser/KaliLinux                                 | PenTest             | IAM      | Medium   |
| PenTest:IAMUser/ParrotLinux                               | PenTest             | IAM      | Medium   |
| PenTest:IAMUser/PentooLinux                               | PenTest             | IAM      | Medium   |
| Persistence:IAMUser/NetworkPermissions                    | Persistence         | IAM      | Medium*  |
| Persistence:IAMUser/ResourcePermissions                   | Persistence         | IAM      | Medium*  |
| Persistence:IAMUser/UserPermissions                       | Persistence         | IAM      | Medium*  |
| Policy:IAMUser/RootCredentialUsage                        | Policy              | IAM      | Low      |
| PrivilegeEscalation:IAMUser/AdministrativePermissions     | PrivilegeEscalation | IAM      | Low*     |
| Recon:IAMUser/MaliciousIPCaller                           | Recon               | IAM      | Medium   |
| Recon:IAMUser/MaliciousIPCaller.Custom                    | Recon               | IAM      | Medium   |
| Recon:IAMUser/NetworkPermissions                          | Recon               | IAM      | Medium*  |
| Recon:IAMUser/ResourcePermissions                         | Recon               | IAM      | Medium*  |
| Recon:IAMUser/TorIPCaller                                 | Recon               | IAM      | Medium   |
| Recon:IAMUser/UserPermissions                             | Recon               | IAM      | Medium*  |
| ResourceConsumption:IAMUser/ComputeResources              | ResourceConsumption | IAM      | Medium*  |
| Stealth:IAMUser/CloudTrailLoggingDisabled                 | Stealth             | IAM      | Low      |
| Stealth:IAMUser/LoggingConfigurationModified              | Stealth             | IAM      | Medium*  |
| Stealth:IAMUser/PasswordPolicyChange                      | Stealth             | IAM      | Low      |
| UnauthorizedAccess:IAMUser/ConsoleLogin                   | UnauthorizedAccess  | IAM      | Medium*  |
| UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B          | UnauthorizedAccess  | IAM      | Medium   |
| UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration | UnauthorizedAccess  | IAM      | High     |
| UnauthorizedAccess:IAMUser/MaliciousIPCaller              | UnauthorizedAccess  | IAM      | Medium   |
| UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom       | UnauthorizedAccess  | IAM      | Medium   |
| UnauthorizedAccess:IAMUser/TorIPCaller                    | UnauthorizedAccess  | IAM      | Medium   |
| Discovery:S3/BucketEnumeration.Unusual                    | Discovery           | S3       | Medium   |
| Discovery:S3/MaliciousIPCaller.Custom                     | Discovery           | S3       | High     |
| Discovery:S3/TorIPCaller                                  | Discovery           | S3       | Medium   |
| Exfiltration:S3/ObjectRead.Unusual                        | Exfiltration        | S3       | Medium   |
| Impact:S3/PermissionsModification.Unusual                 | Impact              | S3       | Medium   |
| Impact:S3/ObjectDelete.Unusual                            | Impact              | S3       | Medium   |
| PenTest:S3/KaliLinux                                      | PenTest             | S3       | Medium   |
| PenTest:S3/ParrotLinux                                    | PenTest             | S3       | Medium   |
| PenTest:S3/PentooLinux                                    | PenTest             | S3       | Medium   |
| Policy:S3/AccountBlockPublicAccessDisabled                | Policy              | S3       | Low      |
| Policy:S3/BucketBlockPublicAccessDisabled                 | Policy              | S3       | Low      |
| Policy:S3/BucketAnonymousAccessGranted                    | Policy              | S3       | High     |
| Policy:S3/BucketPublicAccessGranted                       | Policy              | S3       | High     |
| Stealth:S3/ServerAccessLoggingDisabled                    | Stealth             | S3       | Low      |
| UnauthorizedAccess:S3/MaliciousIPCaller.Custom            | UnauthorizedAccess  | S3       | High     |
| UnauthorizedAccess:S3/TorIPCaller                         | UnauthorizedAccess  | S3       | High     |

https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
