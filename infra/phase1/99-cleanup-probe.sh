#!/usr/bin/env bash
# Terminate the probe instance and delete its security group.
# The base AMI and the IAM role are kept for the next steps; pass --all to
# delete the role as well.
#
# Usage: ./99-cleanup-probe.sh <instance-id> [--all]
set -euo pipefail
cd "$(dirname "$0")"
. ./lib.sh
need aws

ID="${1:-}"
[ -n "$ID" ] || die "usage: $0 <instance-id> [--all]"
REGION="$(region)"
aws_ready

SG="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" \
	--query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text)"

log "terminating $ID"
aws ec2 terminate-instances --region "$REGION" --instance-ids "$ID" >/dev/null
aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$ID"

if [ "$SG" != None ] && [ -n "$SG" ]; then
	log "deleting security group $SG"
	aws ec2 delete-security-group --region "$REGION" --group-id "$SG" || true
fi

if [ "${2:-}" = "--all" ]; then
	ROLE=nodetrust-probe-ssm
	log "deleting IAM role $ROLE"
	aws iam remove-role-from-instance-profile --instance-profile-name "$ROLE" --role-name "$ROLE" || true
	aws iam delete-instance-profile --instance-profile-name "$ROLE" || true
	aws iam detach-role-policy --role-name "$ROLE" \
		--policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore || true
	aws iam delete-role --role-name "$ROLE" || true
fi
