# automated-cspm-remediation-pipeline
This phase builds a detect-and-fix loop: Access Analyzer spots a role that anyone on the internet could assume, EventBridge passes that finding to a Lambda function, and the Lambda rewrites the trust policy to something safe.

**Step 1: Deploy the vulnerable role**
No permissions policies will be attached to this role. A trust policy of "AWS": "*" lets any AWS account assume it. With no permissions attached, nobody can do anything with it, even if they get in. The role will be deleted once the lab is finished.

I). I'm going to create the vulnerable role using AWS CloudShell. To do that, sign in to the AWS console, switch to the region you’re using for this lab, and click the CloudShell icon (a small >_ box) in the top navigation bar: 

<img width="2609" height="102" alt="image" src="https://github.com/user-attachments/assets/8695e72e-bd59-40e7-8a7a-88ae5db6f2d0" />

Confirm your account with the command: _aws sts get-caller-identity_

It'll reveal your account details: 

<img width="702" height="171" alt="image" src="https://github.com/user-attachments/assets/c408d07a-69ed-40f7-bea5-4718d77de284" />

II). Create the trust policy file. The trust policy is attached to an IAM role, and it defines who (or what) is allowed to assume that role. Think of it as the role's "gatekeeper." Before an entity can use a role's permissions, it must first be trusted by the role's trust policy. 

Paste this file into AWS CloudShell: 

<img width="1472" height="590" alt="image" src="https://github.com/user-attachments/assets/e1d8a3e9-470b-4e2f-9764-5726e48a0feb" />

cat > open-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "*" },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

Check that it saved correctly with this command: _cat open-trust.json_ 

Your result should look like this: 

<img width="945" height="365" alt="image" src="https://github.com/user-attachments/assets/9e1bf1ad-6882-4da6-a60a-da7b0091653a" />

III). Create the role using this command: 

aws iam create-role \
  --role-name Panopticon-Test-Role \
  --assume-role-policy-document file://open-trust.json \
  --description "Intentionally vulnerable role for CSPM remediation lab" \
  --tags Key=project,Value=panopticon Key=purpose,Value=lab-test

  If it's successful, you'll see the role’s ARN, RoleId, and the trust policy, as shown below:

  <img width="1536" height="1087" alt="image" src="https://github.com/user-attachments/assets/d47b63d7-6e20-41e6-918a-f131211f941a" />

IV). Confirm the trust policy is open with this command: 

aws iam get-role \
  --role-name Panopticon-Test-Role \
  --query 'Role.AssumeRolePolicyDocument'

  If it's open, you'll see this: "Principal": {"AWS": "*"}, as shown below: 

  <img width="907" height="474" alt="image" src="https://github.com/user-attachments/assets/71114e47-8280-48c9-b00b-43e78a5d4f80" />

  Then confirm the role has no attached permissions with these commands: _aws iam list-attached-role-policies --role-name Panopticon-Test-Role
aws iam list-role-policies --role-name Panopticon-Test-Role_

Both commands should produce an empty list: 

<img width="1132" height="314" alt="image" src="https://github.com/user-attachments/assets/9c98219c-b7ba-437d-8dc3-f35cd43fd622" />

**Step 2: Step 2: Build the Panopticon Engine Lambda**

This step comes before Access Analyzer so the pipeline is ready to receive findings.

I). Set the variables using this command: 

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$AWS_REGION
echo "Account: $ACCOUNT_ID | Region: $REGION"

<img width="1119" height="194" alt="image" src="https://github.com/user-attachments/assets/543fb8c9-beeb-4250-b2de-6fe292b1d361" />

II) Create the Lambda execution role. The first step is to let Lambda assume the trust policy role using this JSON file: 

<img width="1379" height="686" alt="image" src="https://github.com/user-attachments/assets/94488a10-4cda-4847-b136-228040137d5b" />

Then create the Lambda role using this command: 

aws iam create-role \
  --role-name Panopticon-Engine-ExecRole \
  --assume-role-policy-document file://lambda-trust.json \
  --description "Execution role for Panopticon Engine remediation Lambda" \
  --tags Key=project,Value=panopticon

<img width="1374" height="963" alt="image" src="https://github.com/user-attachments/assets/ab884909-3fb2-4056-8363-b8b98924ee37" />

III). Attach CloudWatch logging permissions using this command: 

aws iam attach-role-policy \
  --role-name Panopticon-Engine-ExecRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

IV). Write the remediation permissions policy: This heredoc uses an unquoted EOF so that $ACCOUNT_ID gets filled in automatically:

<img width="1469" height="1037" alt="image" src="https://github.com/user-attachments/assets/b8dbf15a-3bad-4679-9d25-204569d4a0c6" />

If it works correctly, the Resource line should show your real account ID, not ${ACCOUNT_ID}, like this:


<img width="1737" height="1109" alt="image" src="https://github.com/user-attachments/assets/4bfa139c-411b-4d2a-b043-350ddf2f5356" />

IV). Attach the policy as an inline policy with this command: 

aws iam put-role-policy \
  --role-name Panopticon-Engine-ExecRole \
  --policy-name Panopticon-Remediation \
  --policy-document file://engine-permissions.json

V). Wait for IAM to propagate using this command: sleep 15

A newly created role takes a few seconds to become usable everywhere in AWS. Without this pause, the next step often fails with an error saying the role cannot be assumed by Lambda.

VI). Write the functional code**

mkdir -p ~/panopticon-engine && cd ~/panopticon-engine

cat > lambda_function.py << 'EOF'
import json
import logging
import os
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client("iam")
analyzer = boto3.client("accessanalyzer")

ROLE_PREFIX = os.environ.get("TARGET_ROLE_PREFIX", "Panopticon-")


def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))
    detail = event.get("detail", {})

    # Only act on active findings about IAM roles
    if detail.get("resourceType") != "AWS::IAM::Role" or detail.get("status") != "ACTIVE":
        logger.info("Not an active IAM role finding. Skipping.")
        return {"status": "skipped"}

    role_arn = detail["resource"]
    role_name = role_arn.split("/")[-1]
    account_id = detail.get("accountId") or role_arn.split(":")[4]

    # Safety guard: never touch roles outside the lab scope
    if not role_name.startswith(ROLE_PREFIX):
        logger.warning("Role %s is outside remediation scope. Skipping.", role_name)
        return {"status": "out_of_scope", "role": role_name}

    # Replace the open trust with one that only trusts this account
    safe_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole"
        }]
    }

    iam.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=json.dumps(safe_trust)
    )

    # Leave an audit trail on the role itself
    now = datetime.now(timezone.utc).isoformat()
    iam.tag_role(RoleName=role_name, Tags=[
        {"Key": "panopticon:remediated-at", "Value": now},
        {"Key": "panopticon:finding-id", "Value": detail.get("id", "unknown")}
    ])

    # Ask Access Analyzer to re-check, so the finding moves to Resolved
    try:
        analyzer.start_resource_scan(
            analyzerArn=detail["analyzerArn"],
            resourceArn=role_arn
        )
    except Exception as e:
        logger.warning("Rescan request failed (non-fatal): %s", e)

    logger.info("REMEDIATED %s at %s", role_name, now)
    return {"status": "remediated", "role": role_name, "remediated_at": now}
EOF

Then run a quick syntax check with this command: _python3 -m py_compile lambda_function.py_

No output means the code is fine:

<img width="1041" height="109" alt="image" src="https://github.com/user-attachments/assets/71db743e-bdd3-4ada-89c3-afd67589633c" />

VII). Package the code as a zip file using this command (Lambda deployments must be uploaded as a zip file): zip function.zip lambda_function.py

<img width="907" height="108" alt="image" src="https://github.com/user-attachments/assets/345119c8-39cb-4822-9a42-60e240ad5906" />

IX). Create the function using this command: 

aws lambda create-function \
  --function-name Panopticon-Engine \
  --runtime python3.12 \
  --role arn:aws:iam::${ACCOUNT_ID}:role/Panopticon-Engine-ExecRole \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://function.zip \
  --timeout 30 \
  --environment "Variables={TARGET_ROLE_PREFIX=Panopticon-}" \
  --tags project=panopticon

  <img width="1588" height="1374" alt="image" src="https://github.com/user-attachments/assets/669b2e97-c2c8-4efa-8ebf-d50eb3d1be26" />

Verify the function with this command (wait until it's ready): _aws lambda wait function-active-v2 --function-name Panopticon-Engine_

Then check its configuration (You’re looking for "State": "Active" and "Timeout": 30.) with this command:

aws lambda get-function-configuration \
  --function-name Panopticon-Engine \
  --query '{State:State, Runtime:Runtime, Timeout:Timeout, Role:Role, Handler:Handler}'

  <img width="1121" height="275" alt="image" src="https://github.com/user-attachments/assets/33a94082-12de-4768-b5a3-c0f6ea05574f" />

 x). Perform a smoke test by sending a harmless event that isn’t about an IAM role. The function should skip it without touching anything. The expected output {"status": "skipped"}.

 The command for the smoke test: 

aws lambda invoke \
  --function-name Panopticon-Engine \
  --cli-binary-format raw-in-base64-out \
  --payload '{"detail": {"resourceType": "AWS::S3::Bucket", "status": "ACTIVE"}}' \
  response.json && cat response.json

The expected result: 

<img width="985" height="271" alt="image" src="https://github.com/user-attachments/assets/b8a08b8d-14d1-4b43-a976-bb0a90dbdef4" />


**Step 3: Wire EventBridge to the Lambda**

I). If CloudShell has restarted since Step 2, use this command to reset the variables. All three values should print. If FUNCTION_ARN is blank, you’re in a different region from Step 2. Switch regions in the console’s top bar, and CloudShell will reopen in that region.

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$AWS_REGION
FUNCTION_ARN=$(aws lambda get-function --function-name Panopticon-Engine --query 'Configuration.FunctionArn' --output text)
echo "Account: $ACCOUNT_ID | Region: $REGION"
echo "Lambda: $FUNCTION_ARN"

II). Write the event pattern. This filter means the rule only fires for active Access Analyzer findings about IAM roles. Findings about S3 buckets or KMS keys, and findings that are already resolved, never reach your Lambda. This is the command you need for this step:

mkdir -p ~/panopticon-eventbridge && cd ~/panopticon-eventbridge

cat > event-pattern.json << 'EOF'
{
  "source": ["aws.access-analyzer"],
  "detail-type": ["Access Analyzer Finding"],
  "detail": {
    "resourceType": ["AWS::IAM::Role"],
    "status": ["ACTIVE"]
  }
}
EOF

III). Create the rule. The command returns a RuleArn. Save it in a variable for the next step. The command you need to create the rule: 

RULE_ARN=$(aws events describe-rule --name Panopticon-AccessAnalyzer-Findings --query Arn --output text)
echo $RULE_ARN

The result: 

<img width="1237" height="292" alt="image" src="https://github.com/user-attachments/assets/c7430273-7cb2-40e8-b120-d798c63af2c2" />

Save the variable with this command: RULE_ARN=$(aws events describe-rule --name Panopticon-AccessAnalyzer-Findings --query Arn --output text)
echo $RULE_ARN

IV). Allow EventBridge to invoke Lambda (This adds a resource-based policy to the Lambda. The --source-arn limits it so that only this specific rule can trigger the function, not every EventBridge rule in your account. This is the same least-privilege idea as the Panopticon-* scope on the execution role): 

aws lambda add-permission \
  --function-name Panopticon-Engine \
  --statement-id AllowEventBridgeInvoke \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn $RULE_ARN

  <img width="3338" height="346" alt="image" src="https://github.com/user-attachments/assets/29d8d577-6cd4-4e04-ad5c-722d012c0ea6" />

  V). Attach the Lambda as the rule’s target (the output should show "FailedEntryCount": 0) with this command: 
  
  aws events put-targets \
  --rule Panopticon-AccessAnalyzer-Findings \
  --targets "Id"="PanopticonEngine","Arn"="$FUNCTION_ARN"

  <img width="927" height="175" alt="image" src="https://github.com/user-attachments/assets/74466551-4e52-4265-bf06-ef54ab019464" />

VI). Verify the wiring. Check that the rule is enabled and has the right pattern:

aws events describe-rule \
  --name Panopticon-AccessAnalyzer-Findings \
  --query '{State:State, Pattern:EventPattern}'

  <img width="2379" height="213" alt="image" src="https://github.com/user-attachments/assets/ade4dafd-fafb-41e2-855b-3d6ff4e18e64" />

 Check that the target is attached with this command: _aws events list-targets-by-rule --rule Panopticon-AccessAnalyzer-Findings_

<img width="1134" height="244" alt="image" src="https://github.com/user-attachments/assets/46e51e81-903a-4506-a1ef-ee9bb4c43f7f" />

Check that the Lambda grants EventBridge permission to invoke it. In the last output, look for "Service": "events.amazonaws.com" and your rule’s ARN under AWS:SourceArn.

The command: aws lambda get-policy --function-name Panopticon-Engine --query Policy --output text | python3 -m json.tool

The result: 

<img width="1669" height="572" alt="image" src="https://github.com/user-attachments/assets/96ef5446-4bba-476a-93c3-1ca36a81ae17" />

VII). 7. Test the event pattern. You can’t send a fake Access Analyzer event through EventBridge, because AWS reserves aws.* sources for its own services. You can still confirm your pattern would match a real finding using EventBridge’s built-in pattern tester.

First, create a sample event using this: 

<img width="1173" height="822" alt="image" src="https://github.com/user-attachments/assets/5c9ed52c-b7b9-451c-9f71-d3c4f10f65fd" />

Then run a matching test with this command: 

aws events test-event-pattern \
  --event-pattern file://event-pattern.json \
  --event file://sample-event.json

The result should show "Result": true, as seen here: 

<img width="913" height="643" alt="image" src="https://github.com/user-attachments/assets/11838d95-e9aa-480b-80ae-21b68910e768" />

**Step 4: Turn on IAM Access Analyzer**

I). Set variables and note the starting time. Write down START_TIME. It’s the first timestamp for your detection-latency measurement.

The command to set the variable: 

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$AWS_REGION
START_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "Account: $ACCOUNT_ID | Region: $REGION | Started: $START_TIME"

<img width="1325" height="295" alt="image" src="https://github.com/user-attachments/assets/babef993-b272-4d3d-8327-9d6b5c7c8648" />

II). Check for an existing analyzer with this command: 

aws accessanalyzer list-analyzers --type ACCOUNT \
  --query 'analyzers[].{Name:name, Status:status, Arn:arn}'

If this returns [], continue to step 3: 

<img width="805" height="62" alt="image" src="https://github.com/user-attachments/assets/3bbe4406-862c-44b2-a99c-c5e1222ac34e" />

III). Create the analyzer with this command: 

aws accessanalyzer create-analyzer \
  --analyzer-name panopticon-analyzer \
  --type ACCOUNT \
  --tags project=panopticon

--type ACCOUNT makes my account the zone of trust. Any access granted to a principal outside the account gets flagged, and "AWS": "*" covers every account in the world.

Then save the ARN in a variable and in a file with this command: 

ANALYZER_ARN=$(aws accessanalyzer get-analyzer --analyzer-name panopticon-analyzer --query 'analyzer.arn' --output text)
echo $ANALYZER_ARN
echo $ANALYZER_ARN > ~/analyzer-arn.txt

<img width="1424" height="149" alt="image" src="https://github.com/user-attachments/assets/222b52ca-1b11-4d17-a241-03aca610daee" />

The file survives CloudShell restarts, so you can get the ARN back with this: _ANALYZER_ARN=$(cat ~/analyzer-arn.txt)._

IV). Wait for the status to become active with this command: 

aws accessanalyzer get-analyzer --analyzer-name panopticon-analyzer \
  --query 'analyzer.{Status:status, Reason:statusReason}'

The status starts as CREATING and changes to ACTIVE once the first scan finishes. Rerun the command every 30 seconds or so. A small account usually finishes within a few minutes.

<img width="1439" height="247" alt="image" src="https://github.com/user-attachments/assets/65893242-ae5c-40e3-a3a6-185018d94ee5" />

V). Look for the finding with this command: 

aws accessanalyzer list-findings \
  --analyzer-arn $ANALYZER_ARN \
  --filter '{"resourceType": {"eq": ["AWS::IAM::Role"]}}' \
  --query 'findings[].{Resource:resource, Status:status, Public:isPublic, Created:createdAt, Updated:updatedAt, Id:id}' \
  --output table

<img width="2782" height="378" alt="image" src="https://github.com/user-attachments/assets/80c3aaca-84bf-46db-b95f-d1263006e72b" />

VI). Check whether the pipeline has already fired. The finding’s status tells you what happened:

ACTIVE: the role has been flagged but not fixed yet, or the remediation is still in progress. Wait a minute and check again.
RESOLVED: the Lambda caught the finding, rewrote the trust policy, and Access Analyzer confirmed the fix. The pipeline worked end to end on its first real event.

To confirm, check the Lambda logs with this command: aws logs tail /aws/lambda/Panopticon-Engine --since 30m --format short | grep -E "REMEDIATED|Skipping|ERROR"

Then check the role’s trust policy and tags with this command: 

aws iam get-role --role-name Panopticon-Test-Role \
  --query 'Role.AssumeRolePolicyDocument.Statement[0].Principal'

aws iam list-role-tags --role-name Panopticon-Test-Role --output table

If remediation ran, the principal shows arn:aws:iam::<your-account>:root and the tags include panopticon:remediated-at, like this: 


<img width="977" height="520" alt="image" src="https://github.com/user-attachments/assets/6202995d-84a6-4895-885f-5d158b7cd1b8" />

VII). Record your timestamps. Get the full details of the finding with this command:


FINDING_ID=$(aws accessanalyzer list-findings --analyzer-arn $ANALYZER_ARN \
  --filter '{"resource": {"contains": ["Panopticon-Test-Role"]}}' \
  --query 'findings[0].id' --output text)

aws accessanalyzer get-finding --analyzer-arn $ANALYZER_ARN --id $FINDING_ID \
  --query 'finding.{Created:createdAt, Analyzed:analyzedAt, Updated:updatedAt, Status:status, Principal:principal}'

<img width="1568" height="344" alt="image" src="https://github.com/user-attachments/assets/6bdf5526-912b-4a06-bae9-1547676d43e2" />

**Step 5: Test the pipeline**

This has two tests: 

Test A (manual invoke) calls the Lambda directly with a fake finding. It proves the remediation code works, independent of Access Analyzer and EventBridge.
Test B (live) reopens the trust policy and lets the real chain catch it with no help from you. This is the test that gives you clean latency numbers, because the analyzer’s initial scan isn’t mixed in this time.

I). The setup. Use this command to open the open-trust json file: 

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$AWS_REGION
ANALYZER_ARN=$(cat ~/analyzer-arn.txt)
mkdir -p ~/panopticon-tests && cd ~/panopticon-tests
ls ~/open-trust.json

<img width="887" height="198" alt="image" src="https://github.com/user-attachments/assets/0f390846-3150-4812-be7a-8668428ce600" />

II). Then use the following helper to print the role’s current principal. You’ll use it throughout:

principal() {
  aws iam get-role --role-name Panopticon-Test-Role \
    --query 'Role.AssumeRolePolicyDocument.Statement[0].Principal.AWS' --output text
}
principal

It'll print your account root's ARN: 

<img width="1024" height="155" alt="image" src="https://github.com/user-attachments/assets/c5340651-64b9-48e0-9509-a732ea033cdd" />

III). Test A: Manual invoke (proves the code)

A1). Reopen the role with this command: 

aws iam update-assume-role-policy \
  --role-name Panopticon-Test-Role \
  --policy-document file://$HOME/open-trust.json
principal

This should print * like this: 

<img width="677" height="145" alt="image" src="https://github.com/user-attachments/assets/14da5edc-3aff-4477-9ee1-3f2c7582d7b0" />

A2). Build a test event with this command: 

cat > test-event.json << EOF
{
  "source": "aws.access-analyzer",
  "detail-type": "Access Analyzer Finding",
  "detail": {
    "id": "manual-test-001",
    "status": "ACTIVE",
    "resourceType": "AWS::IAM::Role",
    "resource": "arn:aws:iam::${ACCOUNT_ID}:role/Panopticon-Test-Role",
    "accountId": "${ACCOUNT_ID}",
    "isPublic": true,
    "principal": { "AWS": "*" },
    "analyzerArn": "${ANALYZER_ARN}"
  }
}
EOF

A3). Then invoke the Lambda with this: 

aws lambda invoke \
  --function-name Panopticon-Engine \
  --cli-binary-format raw-in-base64-out \
  --payload file://test-event.json \
  response-a.json && cat response-a.json

  The response should say "status": "remediated" like this:

<img width="1499" height="265" alt="image" src="https://github.com/user-attachments/assets/d802efe0-2ef0-45c1-974d-0a329d1fb1a1" />

A4: Verify with this command: 

principal
aws iam list-role-tags --role-name Panopticon-Test-Role \
  --query "Tags[?starts_with(Key,'panopticon:')]" --output table

The principal should be back to your root ARN, and panopticon:finding-id should now read manual-test-001. That proves the tag came from this manual run: 

<img width="874" height="300" alt="image" src="https://github.com/user-attachments/assets/49659f65-bfb7-4e84-9efd-a05b990eb15a" />

Test B: Live end-to-end (proves the pipeline)

B1: Reopen the role and record the start time with this command: 

T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam update-assume-role-policy \
  --role-name Panopticon-Test-Role \
  --policy-document file://$HOME/open-trust.json
echo "Reopened at: $T0"
principal

<img width="828" height="227" alt="image" src="https://github.com/user-attachments/assets/bea15bc7-f41f-40f8-b9f5-b8f122f05eaa" />


B2. Watch for the automatic fix. Don’t touch anything else. This loop checks the role every 10 seconds and stops when the principal changes with this command: 

principal() {
  aws iam get-role --role-name Panopticon-Test-Role \
    --query 'Role.AssumeRolePolicyDocument.Statement[0].Principal.AWS' --output text
}

T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam update-assume-role-policy \
  --role-name Panopticon-Test-Role \
  --policy-document file://$HOME/open-trust.json
echo "Reopened at: $T0"

or 

while true; do
  P=$(principal)
  echo "$(date -u +%H:%M:%S)  principal: $P"
  [ "$P" != "*" ] && { T_FIXED=$(date -u +%Y-%m-%dT%H:%M:%SZ); echo "FIXED (observed) at $T_FIXED"; break; }
  sleep 10
done


while true; do
  P=$(principal)
  echo "$(date -u +%H:%M:%S)  principal: $P"
  [ "$P" != "*" ] && { T_FIXED=$(date -u +%Y-%m-%dT%H:%M:%SZ); echo "FIXED (observed) at $T_FIXED"; break; }
  sleep 10
done

The result: 

<img width="1683" height="706" alt="image" src="https://github.com/user-attachments/assets/9319d276-9904-42e8-8b56-d3741d292f65" />

The flooding phase

As a requirement of this project, the EventBridge should be flooded with event bus with 50 duplicate findings for the same vulnerable role simultaneously. Confirm that your error-handling blocks race conditions and successfully resolves without crashing. 

Here's to achieve it. 

Confirm the setup again with this command: 

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$AWS_REGION
ANALYZER_ARN=$(cat ~/analyzer-arn.txt)
FUNCTION_ARN=$(aws lambda get-function --function-name Panopticon-Engine --query 'Configuration.FunctionArn' --output text)
mkdir -p ~/panopticon-tests/test-c && cd ~/panopticon-tests/test-c
echo "$ACCOUNT_ID | $REGION | $FUNCTION_ARN"

Step 1: Then hardene the Lambda with this: 

cd ~/panopticon-engine
cp lambda_function.py lambda_function_v1_backup.py

cat > lambda_function.py << 'EOF'
import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Adaptive retries back off automatically when IAM throttles us
RETRY_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})
iam = boto3.client("iam", config=RETRY_CONFIG)
analyzer = boto3.client("accessanalyzer", config=RETRY_CONFIG)

ROLE_PREFIX = os.environ.get("TARGET_ROLE_PREFIX", "Panopticon-")


def log_result(result, role, **extra):
    """One structured line per invocation so outcomes can be counted."""
    payload = {"panopticon_result": result, "role": role, **extra}
    logger.info(json.dumps(payload))
    return {"status": result, "role": role, **extra}


def is_open(trust_policy):
    """True if any Allow statement trusts a wildcard principal."""
    for stmt in trust_policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws = principal.get("AWS")
            values = aws if isinstance(aws, list) else [aws]
            if "*" in values:
                return True
    return False


def current_trust(role_name):
    return iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]


def lambda_handler(event, context):
    detail = event.get("detail", {})

    if detail.get("resourceType") != "AWS::IAM::Role" or detail.get("status") != "ACTIVE":
        return log_result("skipped", None, reason="not an active IAM role finding")

    role_arn = detail["resource"]
    role_name = role_arn.split("/")[-1]
    account_id = detail.get("accountId") or role_arn.split(":")[4]
    finding_id = detail.get("id", "unknown")

    if not role_name.startswith(ROLE_PREFIX):
        return log_result("out_of_scope", role_name)

    # Idempotency check: is there still anything to fix?
    try:
        if not is_open(current_trust(role_name)):
            return log_result("already_safe", role_name, finding_id=finding_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return log_result("role_missing", role_name)
        raise

    safe_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole"
        }]
    }

    # Race handling: if the write fails, check whether another invocation won
    try:
        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(safe_trust)
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if not is_open(current_trust(role_name)):
            return log_result("already_safe", role_name,
                              finding_id=finding_id, note=f"lost race ({code})")
        raise

    now = datetime.now(timezone.utc).isoformat()

    # Non-critical follow-ups: warn on failure, never crash
    try:
        iam.tag_role(RoleName=role_name, Tags=[
            {"Key": "panopticon:remediated-at", "Value": now},
            {"Key": "panopticon:finding-id", "Value": finding_id}
        ])
    except ClientError as e:
        logger.warning("Tagging failed (non-fatal): %s", e)

    if detail.get("analyzerArn"):
        try:
            analyzer.start_resource_scan(
                analyzerArn=detail["analyzerArn"],
                resourceArn=role_arn
            )
        except ClientError as e:
            logger.warning("Rescan request failed (non-fatal): %s", e)

    return log_result("remediated", role_name, finding_id=finding_id, remediated_at=now)
EOF

python3 -m py_compile lambda_function.py && echo "Syntax OK"
zip -q function.zip lambda_function.py
aws lambda update-function-code --function-name Panopticon-Engine --zip-file fileb://function.zip --query 'LastUpdateStatus'
aws lambda wait function-updated-v2 --function-name Panopticon-Engine && echo "Deployed"


Step 2. Create the stress-test rule with this command:

cd ~/panopticon-tests/test-c

cat > stress-pattern.json << 'EOF'
{
  "source": ["panopticon.stresstest"],
  "detail-type": ["Access Analyzer Finding"]
}
EOF

aws events put-rule \
  --name Panopticon-StressTest \
  --event-pattern file://stress-pattern.json \
  --state ENABLED \
  --description "Test C only: synthetic duplicate findings" \
  --tags Key=project,Value=panopticon

STRESS_RULE_ARN=$(aws events describe-rule --name Panopticon-StressTest --query Arn --output text)

aws lambda add-permission \
  --function-name Panopticon-Engine \
  --statement-id AllowStressTestInvoke \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn $STRESS_RULE_ARN

aws events put-targets \
  --rule Panopticon-StressTest \
  --targets "Id"="PanopticonEngine","Arn"="$FUNCTION_ARN"


The last result command shoud show you thiss: 

<img width="3286" height="1110" alt="image" src="https://github.com/user-attachments/assets/90ab8de1-ce30-4009-a518-b589a60ffbef" />

Step 3: Build 50 identical findings. EventBridge accepts at most 10 events per put-events call, so the 50 events go into 5 batches. The heredoc is unquoted so your account details are filled in:

The command to use: 

The result: 

<img width="1025" height="768" alt="image" src="https://github.com/user-attachments/assets/19933746-d46c-47b3-9610-4167ae6ad4da" />

Step 4: Reopne the role with this: 

aws iam update-assume-role-policy \
  --role-name Panopticon-Test-Role \
  --policy-document file://$HOME/open-trust.json
aws iam get-role --role-name Panopticon-Test-Role \
  --query 'Role.AssumeRolePolicyDocument.Statement[0].Principal.AWS' --output text

This should print *. Without an open role, the test would only prove that 50 invocations can say already_safe, not that they handle a race.

<img width="1208" height="247" alt="image" src="https://github.com/user-attachments/assets/2656ac1a-c1ec-4224-a80e-7748e9bbff2f" /> 

Step 5: Flood the event bus. Fire all 5 batches at the same time. The & sends each call to the background, and wait holds until all of them finish:

The command: 

START_MS=$(date +%s%3N)
START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "Flood started: $START_ISO"

for i in 0 1 2 3 4; do
  aws events put-events --entries file://batch-$i.json \
    --query 'FailedEntryCount' --output text --no-cli-pager &
done
wait
echo "All batches sent"

The result: 

<img width="1905" height="817" alt="image" src="https://github.com/user-attachments/assets/67c1dfa6-a3ec-4210-ae7c-9d9e970f1909" />

**Step 6: Verify the results**

a). Use the command below to verify the final state of the role: 

aws iam get-role --role-name Panopticon-Test-Role \
  --query 'Role.AssumeRolePolicyDocument.Statement[0].Principal.AWS' --output text

The expected result is your root ARN: 

<img width="1209" height="131" alt="image" src="https://github.com/user-attachments/assets/d3426d5b-b734-425e-a0a6-6c2b77e63b4f" />

b). Use the command below verify the number of invocations: 

aws logs filter-log-events \
  --log-group-name /aws/lambda/Panopticon-Engine \
  --start-time $START_MS \
  --filter-pattern '"START RequestId"' \
  --query 'length(events)'

The expected result is 50. If the count is lower, wait another minute and rerun, since logs can arrive late: 

<img width="781" height="178" alt="image" src="https://github.com/user-attachments/assets/88de0f7f-76a8-4396-8093-c4262cdc6afc" />

c). Use the command below to determine the outcome breakdown

aws logs filter-log-events \
  --log-group-name /aws/lambda/Panopticon-Engine \
  --start-time $START_MS \
  --filter-pattern '"panopticon_result"' \
  --query 'events[].message' --output text \
  | grep -o '"panopticon_result": "[a-z_]*"' | sort | uniq -c

The result: 

<img width="936" height="281" alt="image" src="https://github.com/user-attachments/assets/0b006c00-4040-4099-90d2-5cbeb47b17d0" />


d). Determine the crashes with the command below: 

aws logs filter-log-events \
  --log-group-name /aws/lambda/Panopticon-Engine \
  --start-time $START_MS \
  --filter-pattern '?"[ERROR]" ?"Task timed out" ?Traceback' \
  --query 'length(events)'

The expected result is 0, as shown below: 

<img width="933" height="177" alt="image" src="https://github.com/user-attachments/assets/7608fb8b-22da-4687-901d-88fd261a3403" />

e). Use the command below as proof that invocations ran in parallel. 

Each parallel Lambda execution environment writes to its own log stream, so the number of new streams shows how many copies ran at once:

bash
aws logs describe-log-streams \
  --log-group-name /aws/lambda/Panopticon-Engine \
  --order-by LastEventTime --descending --max-items 100 \
  --query "length(logStreams[?firstEventTimestamp >= \`$START_MS\`])" --output text

Any number above 1 proves real concurrency. With 50 events arriving at once, it’s typically somewhere between 10 and 50, as shown below: 

<img width="1213" height="154" alt="image" src="https://github.com/user-attachments/assets/5749bac8-419e-4872-80d3-c7c8a876f1ca" />

f). Use the command below to determine lost recoveries. This may be empty. If any lines appear, they’re your best evidence: they show an invocation that collided with another one, recovered, and exited cleanly instead of crashing.

The command: 

aws logs filter-log-events \
  --log-group-name /aws/lambda/Panopticon-Engine \
  --start-time $START_MS \
  --filter-pattern '"lost race"' \
  --query 'events[].message' --output text

  The result (an empty line): 

<img width="874" height="196" alt="image" src="https://github.com/user-attachments/assets/197f5a5c-5f04-4854-9f76-42275342df6d" />


Step 7: Clean up the test rule

Use this command to clean up: 

aws events remove-targets --rule Panopticon-StressTest --ids PanopticonEngine
aws events delete-rule --name Panopticon-StressTest
aws lambda remove-permission --function-name Panopticon-Engine --statement-id AllowStressTestInvoke

The production rule and the hardened Lambda stay in place. The new version also makes the real pipeline safer, since Access Analyzer can send more than one event for the same finding.
