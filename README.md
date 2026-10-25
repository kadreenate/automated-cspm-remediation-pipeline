# automated-cspm-remediation-pipeline
This phase builds a detect-and-fix loop: Access Analyzer spots a role that anyone on the internet could assume, EventBridge passes that finding to a Lambda function, and the Lambda rewrites the trust policy to something safe.
