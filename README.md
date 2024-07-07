# certs-AWS-SCS-02
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Below writeup is based on [Exam Prep Standard Course: AWS Certified Security - Specialty (SCS-C02 - English)](https://explore.skillbuilder.aws/learn/course/18291/Exam%2520Prep%2520Standard%2520Course%253A%2520AWS%2520Certified%2520Security%2520-%2520Specialty%2520%28SCS-C02%2520-%2520English%29)

# Domains

## Threat Detection and Incident Response

### Task Statement 1.1: Design and implement an incident response plan.

Knowledge of:
-       AWS best practices for incident response
-       Cloud incidents
-       Roles and responsibilities in the incident response plan
-       AWS Security Finding Format (ASFF)

Skills in:
-       Implementing credential invalidation and rotation strategies in response to compromises (for example, by using AWS Identity and Access Management [ IAM ] and AWS Secrets Manager)
-       Isolating AWS resources
-       Designing and implementing playbooks and runbooks for responses to security incidents
-       Deploying security services (for example, AWS Security Hub, Amazon Macie, Amazon GuardDuty, Amazon Inspector, AWS Config, Amazon Detective, AWS Identity and Access Management Access Analyzer)
-       Configuring integrations with native AWS services and third-party services (for example, by using Amazon EventBridge and the ASFF)

### Task Statement 1.2: Detect security threats and anomalies by using AWS services.

Knowledge of:
-       AWS managed security services that detect threats
-       Anomaly and correlation techniques to join data across services
-       Visualizations to identify anomalies
-       Strategies to centralize security findings

Skills in:
-       Evaluating findings from security services (for example, GuardDuty, Security Hub, Macie, AWS Config, IAM Access Analyzer)
-       Searching and correlating security threats across AWS services (for example, by using Detective)
-       Performing queries to validate security events (for example, by using Amazon Athena)
-       Creating metric filters and dashboards to detect anomalous activity (for example, by using Amazon CloudWatch)

### Task Statement 1.3: Respond to compromised resources and workloads.

Knowledge of:
-       AWS Security Incident Response Guide
-       Resource isolation mechanisms
-       Techniques for root cause analysis
-       Data capture mechanisms
-       Log analysis for event validation

Skills in:
-       Automating remediation by using AWS services (for example, AWS Lambda, AWS Step Functions, EventBridge, AWS Systems Manager runbooks, Security Hub, AWS Config)
-       Responding to compromised resources (for example, by isolating Amazon EC2 instances)
-       Investigating and analyzing to conduct root cause analysis (for example, by using Detective)
-       Capturing relevant forensics data from a compromised resource (for example, Amazon Elastic Block Store [Amazon EBS] volume snapshots, memory dump)
-       Querying logs in Amazon S3 for contextual information related to security events (for example, by using Athena)
-       Protecting and preserving forensic artifacts (for example, by using S3 Object Lock, isolated forensic accounts, S3 Lifecycle, and S3 replication)
-       Preparing services for incidents and recovering services after incidents

### Additional Resources
-  [AWS Security and Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/introduction.html)
-  [AWS Security Finding Format (ASFF)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html)
-  [Required attributes](https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html)
-  [Playbooks](https://docs.aws.amazon.com/solutions/latest/automated-security-response-on-aws/playbooks-1.html)
-  [Creating your own runbooks](https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-documents.html)
-  [Runbook](https://wa.aws.amazon.com/wellarchitected/2020-07-02T19-33-23/wat.concept.runbook.en.html)
-  [What is AWS Systems Manager Incident Manager? ](https://docs.aws.amazon.com/incident-manager/latest/userguide/what-is-incident-manager.html)
-  [Working with Systems Manager Automation runbooks in Incident Manager](https://docs.aws.amazon.com/incident-manager/latest/userguide/runbooks.html)
-  [How S3 Object Locks works](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-overview.html)
-  [CAPTCHA and Challenge actions in AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge.html)

## Security Logging and Monitoring

### Task Statement 2.1: Design and implement monitoring and alerting to address security events.

Knowledge of:
-       AWS services that monitor events and provide alarms (for example, CloudWatch, EventBridge)
-       AWS services that automate alerting (for example, Lambda, Amazon Simple Notification Service [Amazon SNS], Security Hub)
-       Tools that monitor metrics and baselines (for example, GuardDuty, Systems Manager)

Skills in:
-       Analyzing architectures to identify monitoring requirements and sources of data for security monitoring
-       Analyzing environments and workloads to determine monitoring requirements
-       Designing environment monitoring and workload monitoring based on business and security requirements
-       Setting up automated tools and scripts to perform regular audits (for example, by creating custom insights in Security Hub)
-       Defining the metrics and thresholds that generate alerts

### Task Statement 2.2: Troubleshoot security monitoring and alerting.

Knowledge of:
-       Configuration of monitoring services (for example, Security Hub)
-       Relevant data that indicates security events

Skills in:
-       Analyzing the service functionality, permissions, and configuration of resources after an event that did not provide visibility or alerting
-       Analyzing and remediating the configuration of a custom application that is not reporting its statistics
-       Evaluating logging and monitoring services for alignment with security requirements

### Task Statement 2.3: Design and implement a logging solution.

Knowledge of:
-       AWS services and features that provide logging capabilities (for example, VPC Flow Logs, DNS logs, AWS CloudTrail, Amazon CloudWatch Logs)
-       Attributes of logging capabilities (for example, log levels, type, verbosity)
-       Log destinations and lifecycle management (for example, retention period)

Skills in:
-       Configuring logging for services and applications
-       Identifying logging requirements and sources for log ingestion
-       Implementing log storage and lifecycle management according to AWS best practices and organizational requirements

### Task Statement 2.4: Troubleshoot logging solutions.

Knowledge of:
-       Capabilities and use cases of AWS services that provide data sources (for example, log level, type, verbosity, cadence, timeliness, immutability)
-       AWS services and features that provide logging capabilities (for example, VPC Flow Logs, DNS logs, CloudTrail, CloudWatch Logs)
-       Access permissions that are necessary for logging

Skills in:
-       Identifying misconfiguration and determining remediation steps for absent access permissions that are necessary for logging (for example, by managing read/write permissions, S3 bucket permissions, public access, and integrity)
-       Determining the cause of missing logs and performing remediation steps

### Task Statement 2.5: Design a log analysis solution.

Knowledge of:
-       Services and tools to analyze captured logs (for example, Athena, CloudWatch Logs filter)
-       Log analysis features of AWS services (for example, CloudWatch Logs Insights, CloudTrail Insights, Security Hub insights)
-       Log format and components (for example, CloudTrail logs)

Skills in:
-       Identifying patterns in logs to indicate anomalies and known threats
-       Normalizing, parsing, and correlating logs

### Additional Resources
Review these materials to learn more about the topics covered in this exam domain:

-  [Using CloudWatch anomaly detection](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Anomaly_Detection.html)
-  [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/introduction.html)
-  [Insights in AWS Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-insights.html)
-  [Logging IP traffic using VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
-  [Flow log record examples](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html)
-  [Troubleshooting access denied error messages](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html)
-  [Centralized Logging with OpenSearch](https://aws.amazon.com/solutions/implementations/centralized-logging-with-opensearch/)
-  [Using CloudTrail to identify unexpected behaviors in individual workloads](https://aws.amazon.com/blogs/security/using-cloudtrail-to-identify-unexpected-behaviors-in-individual-workloads/)


##  Infrastructure Security

### Task Statement 3.1: Design and implement security controls for edge services.

Knowledge of:
-       Security features on edge services (for example, AWS WAF, load balancers, Amazon Route 53, Amazon CloudFront, AWS Shield)
-       Common attacks, threats, and exploits (for example, Open Web Application Security Project [OWASP] Top 10, DDoS)
-       Layered web application architecture

Skills in:
-       Defining edge security strategies for common use cases (for example, public website, serverless app, mobile app backend)
-       Selecting appropriate edge services based on anticipated threats and attacks (for example, OWASP Top 10, DDoS)
-       Selecting appropriate protections based on anticipated vulnerabilities and risks (for example, vulnerable software, applications, libraries)
-       Defining layers of defense by combining edge security services (for example, CloudFront with AWS WAF and load balancers)
-       Applying restrictions at the edge based on various criteria (for example, geography, geolocation, rate limit)
-       Activating logs, metrics, and monitoring around edge services to indicate attacks

### Task Statement 3.2: Design and implement network security controls.

Knowledge of:
-       VPC security mechanisms (for example, security groups, network ACLs, AWS Network Firewall)
-       Inter-VPC connectivity (for example, AWS Transit Gateway, VPC endpoints)
-       Security telemetry sources (for example, Traffic Mirroring, VPC Flow Logs)
-       VPN technology, terminology, and usage
-       On-premises connectivity options (for example, AWS VPN, AWS Direct Connect)

Skills in:
-       Implementing network segmentation based on security requirements (for example, public subnets, private subnets, sensitive VPCs, on-premises connectivity)
-       Designing network controls to permit or prevent network traffic as required (for example, by using security groups, network ACLs, and Network Firewall)
-       Designing network flows to keep data off the public internet (for example, by using Transit Gateway, VPC endpoints, and Lambda in VPCs)
-       Determining which telemetry sources to monitor based on network design, threats, and attacks (for example, load balancer logs, VPC Flow Logs, Traffic Mirroring)
-       Determining redundancy and security workload requirements for communication between on-premises environments and the AWS Cloud
(for example, by using AWS VPN, AWS VPN over Direct Connect, and MACsec)
-       Identifying and removing unnecessary network access
-       Managing network configurations as requirements change (for example, by using AWS Firewall Manager)

### Task Statement 3.3: Design and implement security controls for compute workloads.

Knowledge of:
-       Provisioning and maintenance of EC2 instances (for example, patching, inspecting, creation of snapshots and AMIs, use of EC2 Image Builder)
-       IAM instance roles and IAM service roles
-       Services that scan for vulnerabilities in compute workloads (for example, Amazon Inspector, Amazon Elastic Container Registry [Amazon ECR])
-       Host-based security (for example, firewalls, hardening)

Skills in:
-       Creating hardened EC2 AMIs
-       Applying instance roles and service roles as appropriate to authorize compute workloads
-       Scanning EC2 instances and container images for known vulnerabilities
-       Applying patches across a fleet of EC2 instances or container images
-       Activating host-based security mechanisms (for example, host-based firewalls)
-       Analyzing Amazon Inspector findings and determining appropriate mitigation techniques
-       Passing secrets and credentials securely to compute workloads

### Task Statement 3.4: Troubleshoot network security.

Knowledge of:
-       How to analyze reachability (for example, by using VPC Reachability Analyzer and Amazon Inspector)
-       Fundamental TCP/IP networking concepts (for example, UDP compared with TCP, ports, Open Systems Interconnection [OSI] model, network operating system utilities)
-       How to read relevant log sources (for example, Route 53 logs, AWS WAF logs, VPC Flow Logs)

Skills in:
-       Identifying, interpreting, and prioritizing problems in network connectivity (for example, by using Amazon Inspector Network Reachability)
-       Determining solutions to produce desired network behavior
-       Analyzing log sources to identify problems
-       Capturing traffic samples for problem analysis (for example, by using Traffic Mirroring)

### Additional Resources
-  [AWS Well-Architected Framework’s Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/design-principles.html)
-  [Monitoring with Amazon CloudWatch](https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html) 
-  [AWS Best Practices for DDoS Resiliency](https://docs.aws.amazon.com/whitepapers/latest/aws-best-practices-ddos-resiliency/aws-best-practices-ddos-resiliency.html) 
-  [Website endpoints](https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteEndpoints.html)
-  [Restricting access to files on custom origins](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-overview.html#forward-custom-headers-restrict-access)
-  [Security perspective: compliance and assurance](https://docs.aws.amazon.com/whitepapers/latest/overview-aws-cloud-adoption-framework/security-perspective.html)
-  [MAC Security ](https://docs.aws.amazon.com/directconnect/latest/UserGuide/MACsec.html)
-  [Amazon Elastic Block Store (Amazon EBS)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AmazonEBS.html)
-  [AWS Systems Manager Patch Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager.html)
-  [Understanding findings in Amazon Inspector](https://docs.aws.amazon.com/inspector/latest/user/findings-understanding.html)
-  [Amazon Inspector integration with AWS Security Hub](https://docs.aws.amazon.com/inspector/latest/user/securityhub-integration.html)
-  [What is Reachability Analyzer?](https://docs.aws.amazon.com/vpc/latest/reachability/what-is-reachability-analyzer.html)
-  [What is AWS Global Networks for Transit Gateways?](https://docs.aws.amazon.com/network-manager/latest/tgwnm/what-are-global-networks.html)
-  [Flow log record examples ](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html)
-  [Centralized logging solution on AWS](https://aws.amazon.com/solutions/centralized-logging/?ref=wellarchitected)


## Identity and Access Management

### Task Statement 4.1: Design, implement, and troubleshoot authentication for AWS resources.

Knowledge of:
-       Methods and services for creating and managing identities (for example, federation, identity providers, AWS IAM Identity Center [AWS Single Sign-On], Amazon Cognito)
-       Long-term and temporary credentialing mechanisms
-       How to troubleshoot authentication issues (for example, by using CloudTrail, IAM Access Advisor, and IAM policy simulator)

Skills in:
-       Establishing identity through an authentication system, based on requirements
-       Setting up multi-factor authentication (MFA)
-       Determining when to use AWS Security Token Service (AWS STS) to issue temporary credentials

### Task Statement 4.2: Design, implement, and troubleshoot authorization for AWS resources.

Knowledge of:
-       Different IAM policies (for example, managed policies, inline policies, identity-based policies, resource-based policies, session control policies)
-       Components and impact of a policy (for example, Principal, Action, Resource, Condition)
-       How to troubleshoot authorization issues (for example, by using CloudTrail, IAM Access Advisor, and IAM policy simulator)

Skills in:
-       Constructing attribute-based access control (ABAC) and role-based access control (RBAC) strategies
-       Evaluating IAM policy types for given requirements and workloads
-       Interpreting an IAM policy’s effect on environments and workloads
-       Applying the principle of least privilege across an environment
-       Enforcing proper separation of duties
-       Analyzing access or authorization errors to determine cause or effect
-       Investigating unintended permissions, authorization, or privileges granted to a resource, service, or entity

### Additional Resources
-  [What is IAM?](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html)
-  [Security best practices in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
-  [Managing IAM users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_manage.html)
-  [Example IAM identity-based policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html)
-  [IAM Access Analyzer](http://aws.amazon.com/iam/features/analyze-access/)
-  [Actions, resources, and condition keys for AWS services](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html)
-  [Condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)
-  [Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
-  [What is AWS CloudFormation Guard?](https://docs.aws.amazon.com/cfn-guard/latest/ug/what-is-guard.html)

## Data Protection

### Task Statement 5.1: Design and implement controls that provide confidentiality and integrity for data in transit.

Knowledge of:
-       TLS concepts
-       VPN concepts (for example, IPsec)
-       Secure remote access methods (for example, SSH, RDP over Systems Manager Session Manager)
-       Systems Manager Session Manager concepts
-       How TLS certificates work with various network services and resources (for example, CloudFront, load balancers)

Skills in:
-       Designing secure connectivity between AWS and on-premises networks (for example, by using Direct Connect and VPN gateways)
-       Designing mechanisms to require encryption when connecting to resources (for example, Amazon RDS, Amazon Redshift, CloudFront, Amazon S3, Amazon DynamoDB, load balancers, Amazon Elastic File System [Amazon EFS], Amazon API Gateway)
-       Requiring TLS for AWS API calls (for example, with Amazon S3)
-       Designing mechanisms to forward traffic over secure connections (for example, by using Systems Manager and EC2 Instance Connect)
-       Designing cross-Region networking by using private VIFs and public VIFs

### Task Statement 5.2: Design and implement controls that provide confidentiality and integrity for data at rest.

Knowledge of:
-       Encryption technique selection (for example, client-side, server-side, symmetric, asymmetric)
-       Integrity-checking techniques (for example, hashing algorithms, digital signatures)
-       Resource policies (for example, for DynamoDB, Amazon S3, and AWS Key Management Service [AWS KMS])
-       IAM roles and policies

Skills in:
-       Designing resource policies to restrict access to authorized users (for example, S3 bucket policies, DynamoDB policies)
-       Designing mechanisms to prevent unauthorized public access (for example, S3 Block Public Access, prevention of public snapshots and public AMIs)
-       Configuring services to activate encryption of data at rest (for example, Amazon S3, Amazon RDS, DynamoDB, Amazon Simple Queue Service [Amazon SQS], Amazon EBS, Amazon EFS)
-       Designing mechanisms to protect data integrity by preventing modifications (for example, by using S3 Object Lock, KMS key policies, S3 Glacier Vault Lock, and AWS Backup Vault Lock)
-       Designing encryption at rest by using AWS CloudHSM for relational databases (for example, Amazon RDS, RDS Custom, databases on EC2 instances)
-       Choosing encryption techniques based on business requirements

### Task Statement 5.3: Design and implement controls to manage the lifecycle of data at rest.

Knowledge of:
-       Lifecycle policies
-       Data retention standards

Skills in:
-       Designing S3 Lifecycle mechanisms to retain data for required retention periods (for example, S3 Object Lock, S3 Glacier Vault Lock, S3 Lifecycle policy)
-       Designing automatic lifecycle management for AWS services and resources (for example, Amazon S3, EBS volume snapshots, RDS volume snapshots, AMIs, container images, CloudWatch log groups, Amazon Data Lifecycle Manager)
-       Establishing schedules and retention for AWS Backup across AWS services

### Task Statement 5.4: Design and implement controls to protect credentials, secrets, and cryptographic key materials.

Knowledge of:
-       Secrets Manager
-       Systems Manager Parameter Store
-       Usage and management of symmetric keys and asymmetric keys (for example, AWS KMS)

Skills in:
-       Designing management and rotation of secrets for workloads (for example, database access credentials, API keys, IAM access keys, AWS KMS customer managed keys)
-       Designing KMS key policies to limit key usage to authorized users
-       Establishing mechanisms to import and remove customer-provided key material

### Additional Resources
-  [Encrypting Data-at-Rest and Data-in-Transit](https://docs.aws.amazon.com/whitepapers/latest/logical-separation/encrypting-data-at-rest-and--in-transit.html)
-  [AWS Direct Connect + AWS Site-to-Site VPN](https://docs.aws.amazon.com/whitepapers/latest/aws-vpc-connectivity-options/aws-direct-connect-site-to-site-vpn.html)
-  [Hybrid connectivity VPN](https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/hybrid-connectivity.html)
-  [AWS Direct Connect ](https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/direct-connect.html)
-  [Building a global network using AWS Transit Gateway Inter-Region peering](https://aws.amazon.com/blogs/networking-and-content-delivery/building-a-global-network-using-aws-transit-gateway-inter-region-peering/)
-  [AWS Prescriptive Guidance Encryption best practices and features for AWS services](https://docs.aws.amazon.com/pdfs/prescriptive-guidance/latest/encryption-best-practices/encryption-best-practices.pdf)
-  [AWS Certificate Manager ](https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html)
-  [Amazon EC2 Instance Connect (EIC) Endpoint](https://aws.amazon.com/about-aws/whats-new/2023/06/amazon-ec2-instance-connect-ssh-rdp-public-ip-address/)
-  [Secure Connectivity from Public to Private: Introducing EC2 Instance Connect Endpoint](https://aws.amazon.com/blogs/compute/secure-connectivity-from-public-to-private-introducing-ec2-instance-connect-endpoint-june-13-2023/)
-  [Manage your storage lifecycle](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html)
-  [Managing backups using backup plans](https://docs.aws.amazon.com/aws-backup/latest/devguide/about-backup-plans.html)
-  [AWS KMS concepts](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)
-  [Asymmetric keys in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html)
-  [Grants is AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/grants.html)
-  [What is AWS Nitro Enclaves?](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)

## Management and Security Governance

### Task Statement 6.1: Develop a strategy to centrally deploy and manage AWSaccounts.

Knowledge of:
-       Multi-account strategies
-       Managed services that allow delegated administration
-       Policy-defined guardrails
-       Root account best practices
-       Cross-account roles

Skills in:
-       Deploying and configuring AWS Organizations
-       Determining when and how to deploy AWS Control Tower (for example, which services must be deactivated for successful deployment)
-       Implementing SCPs as a technical solution to enforce a policy (for example, limitations on the use of a root account, implementation of controls in AWS Control Tower)
-       Centrally managing security services and aggregating findings (for example, by using delegated administration and AWS Config aggregators)
-       Securing AWS account root user credentials

### Task Statement 6.2: Implement a secure and consistent deployment strategy for cloud resources.

Knowledge of:
-       Deployment best practices with infrastructure as code (IaC) (for example, AWS CloudFormation template hardening and drift detection)
-       Best practices for tagging
-       Centralized management, deployment, and versioning of AWS services
-       Visibility and control over AWS infrastructure

Skills in:
-       Using CloudFormation to deploy cloud resources consistently and securely
-       Implementing and enforcing multi-account tagging strategies
-       Configuring and deploying portfolios of approved AWS services (for example, by using AWS Service Catalog)
-       Organizing AWS resources into different groups for management
-       Deploying Firewall Manager to enforce policies
-       Securely sharing resources across AWS accounts (for example, by using AWS Resource Access Manager [AWS RAM])

### Task Statement 6.3: Evaluate the compliance of AWS resources.

Knowledge of:
-       Data classification by using AWS services
-       How to assess, audit, and evaluate the configurations of AWS resources (for example, by using AWS Config)

Skills in:
-       Identifying sensitive data by using Macie
-       Creating AWS Config rules for detection of noncompliant AWS resources
-       Collecting and organizing evidence by using Security Hub and AWS Audit Manager Task Statement 6.4: Identify security gaps through architectural reviews and cost analysis.

Knowledge of:
-       AWS cost and usage for anomaly identification
-       Strategies to reduce attack surfaces
-       AWS Well-Architected Framework

Skills in:
-       Identifying anomalies based on resource utilization and trends
-       Identifying unused resources by using AWS services and tools (for example, AWS Trusted Advisor, AWS Cost Explorer)
-       Using the AWS Well-Architected Tool to identify security gaps

### Additional Resources
-  [Governance](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/governance.html)
-  [Security](https://docs.aws.amazon.com/wellarchitected/latest/framework/security.html)
-  [Learn template basics](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/gettingstarted.templatebasics.html)
-  [Working with AWS Firewall Manager policies](https://docs.aws.amazon.com/waf/latest/developerguide/working-with-policies.html)
-  [Getting started with an AWS CloudFormation product](https://docs.aws.amazon.com/servicecatalog/latest/adminguide/getstarted-CFN.html)
-  [AWS Config and AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/services-that-can-integrate-config.html)
-  [AWS Audit Manager evidence](https://docs.aws.amazon.com/audit-manager/latest/userguide/evidence-finder.html#understanding-evidence-finder)
-  [Mitigation techniques](https://docs.aws.amazon.com/whitepapers/latest/aws-best-practices-ddos-resiliency/mitigation-techniques.html)
-  [Using CloudWatch anomaly detection](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Anomaly_Detection.html)
-  [Guidance for baseline security assessment on AWS](https://aws.amazon.com/solutions/guidance/baseline-security-assessment-on-aws/#:~:text=Use%20the%20provided%20AWS%20CloudFormation,how%20to%20resolve%20the%20issues.)

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Cheatsheets vs syllabus
AWS services and features 
Note: Security affects all AWS services. Many services do not appear in this list because the overall service is 
out of scope, but the security aspects of the service are in scope. For example, a candidate for this exam would 
not be asked about the steps to set up replication for an S3 bucket, but the candidate might be asked about 
configuring an S3 bucket policy. 

## Management and Governance: 
- [AWS Audit Manager](https://tutorialsdojo.com/aws-audit-manager/) 
- [AWS CloudTrail](https://tutorialsdojo.com/aws-cloudtrail/) 
- -- labs:
- -- [Triggering Events with CloudTrail Logs](https://learn.acloud.guru/handson/c80bd323-11ca-49a6-9028-96752e8f21fd)
- -- [Monitoring, Auditing, and Logging Users and Resource Usage in AWS IAM](https://learn.acloud.guru/handson/9c173560-f318-4a3a-97fa-341bdbdc76a3)
- -- [Using AWS Config and CloudTrail](https://learn.acloud.guru/handson/8a520336-4709-4e12-8636-0d68e2e00273)
- [Amazon CloudWatch](https://tutorialsdojo.com/amazon-cloudwatch/) 
-  [CloudTrail vs CloudWatch](https://tutorialsdojo.com/aws-cloudtrail-vs-amazon-cloudwatch/)
- [AWS Config](https://tutorialsdojo.com/aws-config/) 
- -- labs:
- -- [Setting up Automatic Resource Remediation with AWS Config](https://learn.acloud.guru/handson/bd0330c4-ec18-46b5-b673-3f02eb7cd15c)
- -- [Auditing Resource Compliance with AWS Config](https://learn.acloud.guru/handson/b0e842b6-2254-4a4e-be50-14e01bf8233b)
- [AWS Organizations ](https://tutorialsdojo.com/aws-organizations/)
- [AWS Systems Manager](https://tutorialsdojo.com/aws-systems-manager/) 
- -- labs:
- -- [Creating an IAM Role and Configuring an EC2 Instance for AWS Systems Manager via the AWS Management Console](https://learn.acloud.guru/handson/41fa20fe-7199-4a0a-a02c-e86fb26613c8)
- [AWS Trusted Advisor](https://tutorialsdojo.com/aws-trusted-advisor/)

## Networking and Content Delivery: 
- [Amazon Detective](https://tutorialsdojo.com/amazon-detective/)
- -- labs:
- -- [Detecting Security Issues Using GuardDuty](https://learn.acloud.guru/handson/f3a6e65f-261a-4337-816f-5875ed4dd3e7)
- -- [Adding Dialog to an Alexa Skill](https://learn.acloud.guru/handson/09927777-f170-4502-8c4d-69d3a244a651) 
- [AWS Firewall Manager](https://tutorialsdojo.com/aws-firewall-manager/)
- -- labs:
- -- [Creating and Configuring a WAF](https://learn.acloud.guru/handson/02832161-9dfc-4c5c-8a1b-dd290dbc0050)
- -- [Configuring Centralized Access to the Internet](https://learn.acloud.guru/handson/a0663149-5b0a-4f83-90c8-056f42acb58f)  
- -- [Securing an Application with Multiple AWS Services](https://learn.acloud.guru/handson/fb220576-483e-4b0b-809d-3c02c62e4223)  
- [AWS Network Firewall](https://tutorialsdojo.com/aws-network-firewall/)
- -- labs:
- -- [Configuring an AWS Network Firewall](https://learn.acloud.guru/handson/06ea5cd8-8eb8-4e3a-a679-715f820ee637)
- -- [Implementing AWS Network Firewall](https://learn.acloud.guru/handson/76117bc4-bdb2-4ff6-bc89-551076a52e4f7) 
- [AWS Security Hub](https://tutorialsdojo.com/aws-security-hub/) 
- -- labs:
- -- [Using AWS Security Hub to Analyze an AWS Account](https://learn.acloud.guru/handson/c084edc8-8e1f-4dfe-9c89-237a229f61d0) --> attempted 16th June
- -- [Automating Findings Identified by AWS Security Hub](https://learn.acloud.guru/handson/5b20ca8a-f5d0-479a-8519-719d8d89eddd) 
- -- [Identifying and Remediating Threats with AWS Security Hub](https://learn.acloud.guru/handson/572af34e-00c4-45a4-9a68-4a2e8f0c79d6)
- -- [Implementing AWS Security Hub](https://learn.acloud.guru/handson/0f3e45ce-4103-4c1e-89c6-20e9247383fd) 
- -- [Proactive Security with AWS Security Hub](https://learn.acloud.guru/handson/1072865a-7d87-4ba6-9a6f-d67465b5dd0f)
- -- [Configuring Amazon Inspector with Systems Manager to Assess Application Compliance](https://learn.acloud.guru/handson/609a2394-0815-487e-bb8a-b8f8155c6d4f) 
- [AWS Shield](https://tutorialsdojo.com/aws-shield/) 
- [Amazon VPC](https://tutorialsdojo.com/amazon-vpc/) 
-  o [VPC endpoints](https://tutorialsdojo.com/vpc-interface-endpoint-vs-gateway-endpoint-in-aws/) 
       - labs:
       - [Create a VPC Endpoint and S3 Bucket in AWS](https://learn.acloud.guru/handson/37331c72-e3f1-4ded-9607-61d993fbb5a5)
       - [AWS VPC Endpoints for S3](https://learn.acloud.guru/handson/9256ae5b-e266-40a5-8f6c-5610aae4bac1) 
-  o Network ACLs 
       - labs:
       - [Configuring a Basic VPC in AWS](https://learn.acloud.guru/handson/c30ef1d8-6dff-434d-a484-698027c13d53)
       - [Troubleshooting AWS Network Connectivity: Security Groups and NACLs](https://learn.acloud.guru/handson/cffb7f13-1c46-45cb-886a-f0bb12ff038c) 
-  o Security groups 
-  o Network Access Analyzer 
- [AWS WAF](https://tutorialsdojo.com/aws-waf/)
extras: [IP Blocking: Use AWS WAF or NACL?](https://tutorialsdojo.com/ip-blocking-use-aws-waf-or-nacl/)

## Security, Identity, and Compliance: 
- [AWS Certificate Manager (ACM)](https://tutorialsdojo.com/aws-certificate-manager/) 
- -- labs:
- -- [Configuring a Custom Domain with Cognito](https://learn.acloud.guru/handson/0b77909a-2844-461f-b865-60229e614ad4)
- [AWS CloudHSM ](https://tutorialsdojo.com/aws-cloudhsm/)
- [AWS Directory Service ](https://tutorialsdojo.com/aws-directory-service/)
- [Amazon GuardDuty]()
- -- labs:
- -- [Implementing Amazon GuardDuty and Amazon EventBridge](https://learn.acloud.guru/handson/ec10e337-901c-4524-9d3c-d78eefd921e7)
- -- [Detecting Security Issues Using GuardDuty](https://learn.acloud.guru/handson/f3a6e65f-261a-4337-816f-5875ed4dd3e7)

- [AWS Identity and Access Management (IAM)](https://tutorialsdojo.com/aws-identity-and-access-management-iam/) 
- [Amazon Inspector](https://tutorialsdojo.com/amazon-inspector/) 
- [AWS Key Management Service (AWS KMS) ](https://tutorialsdojo.com/aws-key-management-service-aws-kms/)
- -- labs:
- -- [AWS Security Essentials - KMS Integration with S3](https://learn.acloud.guru/handson/e4e6a251-06af-4046-992b-84f0ece1d3fb)
- [Amazon Macie](https://tutorialsdojo.com/amazon-macie/) 
- AWS Single Sign-On

----------------------------------------------------------------------------------------------------------------------------------------
# Nutshell exam breakdown

## Exam Guide - what to read and understand
[AWS Security Documentation](https://docs.aws.amazon.com/security/)
[AWS Well-Architected - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
[Best Practices for Security, Identity, & Compliance](https://aws.amazon.com/architecture/security-identity-compliance/)
[AWS Best Practices for DDoS Resiliency](https://docs.aws.amazon.com/whitepapers/latest/aws-best-practices-ddos-resiliency/aws-best-practices-ddos-resiliency.html)

## Key AWS Services to Master - don't go, before you know :)
Focus your studies on truly understanding these services inside and out:
- Amazon IAM - Master IAM policies, identity policies vs resource policies, and cross-account access patterns (policy evaluation logic). Know when and how to use IAM groups, roles, identity pools, SAML. There is no excuse here; if you do not feel comfortable with IAM, do not go further. Know well how the 'Condition' statement works in the policy, what types of statements can be used. Understand the difference between identity policy and resource policies, when to use which.
- AWS Key Management Service - Understand encryption key management including automatic vs manual rotation. Know when to use KMS vs CloudHSM.
- Amazon S3 - Know S3 security features like object encryption, bucket policies, ACLs, cross-region replication.
- Amazon VPC - Study VPC security concepts like security groups, NACLs, VPC endpoints, VPC peering. Know how to diagnose connectivity issues.
- Amazon CloudWatch - Learn how to centralize logging and set event-driven alerts and automation.
- Amazon Eventbridge - Learn how to work with data comming from various of AWS services and how to deal with them - messaging, auto-remediation.
- AWS Organizations - A must have, especially the Service Control Policies
- Amazon GuardDuty - Know what it can do, and how automate the remediation.
- Amazon Inspector - Again, have a hands-on knowledge of implementation and remediation, on multiple platforms (EC2, ECR)

## Other Important Services
- Amazon CloudFront,
- AWS WAF,
- AWS Config,
- AWS Lambda,
- Amazon Cognito,
- AWS Systems Manager,
- AWS Secrets Manager,
- Amazon Athena,
- AWS Shield,
- AWS CloudTrail,
