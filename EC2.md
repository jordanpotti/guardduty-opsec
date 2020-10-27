## Backdoor:EC2/C&amp;CActivity.B!DNS

**An EC2 instance is querying a domain name that is associated with a known command and control server.**

**OPSEC Guidelines**

- Make sure your C2 servers are behind Load Balancers or redirectors.
- Leverage tools such as mod_rewrite to restrict and control expectedtraffic to your C2 servers.
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
