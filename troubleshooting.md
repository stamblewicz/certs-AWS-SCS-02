# Domain 1

# Domain 2
## Amazon CloudWatch Logs Agent Troubleshooting

Misconfiguration
● Open the awslogs log file on /var/log/awslogs.log. Check for the following errors:
	○ NocredentialsError
		■ Make sure you attach an IAM role to your EC2 instance.
		■ Alternatively, you can update the IAM user credentials in the /etc/awslogs/awscli.conf file.
	○ AccessDeniedError
		■ Ensure that you have the right permissions for CloudWatch Logs.
● Check if your OS log rotation rules are supported.
● Check for duplicates in the [logstream] section of the agent configuration file.

Insufficient Permissions
● Check if you have the required permissions for the instance’s IAM role:
	○ logs:CreateLogGroup - creates a log group that contains the log stream.
	○ logs:CreateLogStream - creates a log stream. The log stream is the sequence of log events generated from a resource
	○ logs:PutLogEvents - uploads a batch of log events to the log stream.
	○ logs:DescribeLogStreams - this operation lists all the log streams for a particular log group.

Connection Problems
● Check your security group and network access control list’s configuration and verify if it has access to the public Internet.

