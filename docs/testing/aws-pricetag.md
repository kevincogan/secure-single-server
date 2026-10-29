# Create a RHEL gateway test VM on AWS

This is an optional test-host example for the
[remote gateway quickstart](../quickstarts/remote-gateway-pricetag/README.md).
Requires AWS CLI, `jq`, Python 3 and SSH on your workstation.

Run on an AWS administrator workstation from a reviewed checkout of
`redhat-et/secure-single-server`. The AWS helper creates encrypted root disks
and security groups restricted to the workstation's public IPv4 `/32`.
Clone the repository into your preferred parent directory:

```console
cd /path/to/your/projects
git clone https://github.com/redhat-et/secure-single-server.git
cd secure-single-server
```

If already cloned, enter your existing checkout instead. In the same terminal,
configure the AWS session and VM settings:

```console
source scripts/aws/session.sh
aws_test_credentials
REGION=eu-central-1
SUBNET=''
CLIENT_CIDR=''
RUN_PREFIX="pricetag-$(python3 -c 'import uuid; print(uuid.uuid4().hex[:8])')"
SSH_KEY="$HOME/.secure-single-server-tests/ssh/$RUN_PREFIX"
aws_test_discover
aws_test_key
ssh-add "$SSH_KEY"
PRICETAG_VM=(configs/aws/pricetag-cloud.json --scenario remote-gateway \
  --ssh-access restricted --https-access restricted)
```

Review and launch the real-provider server:

```console
aws_test_plan pricetag-real "${PRICETAG_VM[@]}"
aws_test_deploy pricetag-real "${PRICETAG_VM[@]}"
PRICETAG_INSTANCE=$(jq -er '.InstanceId' \
  ".state/$RUN_PREFIX-pricetag-real.json")
aws --region "$REGION" ec2 wait instance-running --instance-ids "$PRICETAG_INSTANCE"
aws_test_verify pricetag-real
```

`aws_test_verify` prints the current SSH host, key path and journal for the
selected VM. If the instance is still pending, rerun the waiter and verify;
never rerun deploy for an instance that already exists. Keep the deployment journal.
The 32-GiB, 150-GiB instance profile is a test starting point, not a capacity
claim. See [AWS operations](aws-operations.md) for restoring a launch session,
printing both VM details, and changing ingress.

## Continue in another terminal

Run this in the workstation terminal used to create the VM. It prints only
connection settings and paths, never AWS credentials, provider keys or SSH key
contents. Copy its output into another Bash or Zsh terminal:

```console
printf 'export RHEL_HOST=%q\nexport SSH_KEY=%q\nexport GATEWAY_HOST=%q\nexport REPO=%q\nexport RUN_PREFIX=%q\nexport REGION=%q\n' "$RHEL_HOST" "$SSH_KEY" "${RHEL_HOST#*@}" "$AWS_TEST_REPO" "$RUN_PREFIX" "$REGION"
printf 'cd "$REPO"\n'
```

Continue at [copy the checkout](../quickstarts/remote-gateway-pricetag/README.md#2-copy-the-checkout).
The destination terminal does not need AWS administrator credentials for SSH,
installation or OpenCode. If the SSH key is encrypted, unlock it there with
`ssh-add "$SSH_KEY"` when needed.
