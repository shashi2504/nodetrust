# Shared helpers for the Phase 1 scripts. Source, do not run.

die() {
	echo "error: $*" >&2
	exit 1
}

need() {
	local c
	for c in "$@"; do
		command -v "$c" >/dev/null 2>&1 || die "'$c' is required but not installed"
	done
}

region() {
	local r="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || true)}}"
	[ -n "$r" ] || die "no AWS region set (export AWS_REGION or run 'aws configure')"
	echo "$r"
}

log() {
	echo "==> $*" >&2
}

# aws_ready fails fast, with AWS's own message, when credentials are missing
# or expired, instead of letting a later call fail with a misleading error.
aws_ready() {
	local err
	err="$(aws sts get-caller-identity --query Account --output text 2>&1 >/dev/null)" ||
		die "AWS credentials are not working: ${err:-unknown error}"
}

# shellcheck disable=SC2034 # used by the scripts that source this file
PROJECT_TAG="Key=project,Value=nodetrust"

# Canonical's prebuilt Secure Boot variable store, pinned to the version the
# base AMI was registered with on 2026-11-15. A different hash stops the build
# so a changed blob is always a deliberate decision.
SB_BLOB_URL="https://github.com/canonical/aws-secureboot-blob/releases/latest/download/blob.bin"
SB_BLOB_SHA256="${SB_BLOB_SHA256:-2361a3dda3d3188c0f9d6d2106a40cc16f22e2c73d5338ddce048e5d0999f34d}"

fetch_sb_blob() { # fetch_sb_blob <dest>
	curl -fsSL -o "$1" "$SB_BLOB_URL"
	local got
	got="$(sha256sum "$1" | cut -d' ' -f1)"
	[ "$got" = "$SB_BLOB_SHA256" ] ||
		die "Secure Boot blob hash is $got, expected $SB_BLOB_SHA256. If Canonical published a new blob on purpose, set SB_BLOB_SHA256 after checking it."
}

# ensure_ssm_role creates the instance role used by probe and builder
# instances: SSM access only, no EC2 or IAM permissions.
SSM_ROLE=nodetrust-probe-ssm
ensure_ssm_role() {
	if aws iam get-role --role-name "$SSM_ROLE" >/dev/null 2>&1; then
		return
	fi
	log "creating IAM role $SSM_ROLE (SSM access only)"
	aws iam create-role --role-name "$SSM_ROLE" \
		--assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
		--tags "$PROJECT_TAG" >/dev/null
	aws iam attach-role-policy --role-name "$SSM_ROLE" \
		--policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
	aws iam create-instance-profile --instance-profile-name "$SSM_ROLE" >/dev/null
	aws iam add-role-to-instance-profile --instance-profile-name "$SSM_ROLE" --role-name "$SSM_ROLE"
	log "waiting 15 s for the instance profile to propagate"
	sleep 15
}

# ensure_no_inbound_sg <region> <name>: prints the ID of a security group in the
# default VPC with no inbound rules, creating it if needed.
ensure_no_inbound_sg() {
	local region="$1" name="$2" vpc sg
	vpc="$(aws ec2 describe-vpcs --region "$region" --filters Name=is-default,Values=true \
		--query 'Vpcs[0].VpcId' --output text)"
	[ "$vpc" != None ] || die "no default VPC in $region; create one with 'aws ec2 create-default-vpc'"
	sg="$(aws ec2 describe-security-groups --region "$region" \
		--filters "Name=group-name,Values=$name" "Name=vpc-id,Values=$vpc" \
		--query 'SecurityGroups[0].GroupId' --output text)"
	if [ "$sg" = None ]; then
		log "creating security group $name (no inbound rules)"
		sg="$(aws ec2 create-security-group --region "$region" --vpc-id "$vpc" \
			--group-name "$name" --description "nodetrust $name: no inbound rules" \
			--tag-specifications "ResourceType=security-group,Tags=[{$PROJECT_TAG}]" \
			--query GroupId --output text)"
	fi
	echo "$sg"
}

# embed_files <template> <out> <placeholder>=<file> ...: replaces each
# placeholder line in the template with the gzip+base64 of the file.
embed_files() {
	local tmpl="$1" out="$2" spec ph file
	shift 2
	cp "$tmpl" "$out"
	for spec in "$@"; do
		ph="${spec%%=*}"
		file="${spec#*=}"
		[ -f "$file" ] || die "$file is missing; extract the complete infra/phase1 folder"
		awk -v ph="$ph" -v data="$(gzip -9c "$file" | base64 -w76)" \
			'{ if ($0 == ph) print data; else print }' "$out" >"$out.tmp"
		mv "$out.tmp" "$out"
	done
	local size
	size="$(wc -c <"$out")"
	[ "$size" -lt 16000 ] || die "user data is $size bytes, over the 16 KB limit"
}

# run_ssm <region> <instance-id> <command>: runs one shell command as root
# through SSM, prints its stdout, and returns 0 only if it succeeded.
run_ssm() {
	local region="$1" id="$2" cmd="$3" cid status
	cid="$(aws ssm send-command --region "$region" --instance-ids "$id" \
		--document-name AWS-RunShellScript \
		--parameters "commands=[\"$cmd\"],executionTimeout=[\"3600\"]" \
		--query Command.CommandId --output text)"
	while :; do
		status="$(aws ssm get-command-invocation --region "$region" --command-id "$cid" --instance-id "$id" \
			--query Status --output text 2>/dev/null || echo Pending)"
		case "$status" in Pending | InProgress | Delayed) sleep 5 ;; *) break ;; esac
	done
	aws ssm get-command-invocation --region "$region" --command-id "$cid" --instance-id "$id" \
		--query StandardOutputContent --output text
	[ "$status" = Success ]
}

# run_ssm_script <region> <instance-id> <script-file> [args...]: ships a local
# script (gzip+base64, so quoting and size stay safe) and runs it as root.
run_ssm_script() {
	local region="$1" id="$2" file="$3" payload
	shift 3
	payload="$(gzip -9c "$file" | base64 -w0)"
	run_ssm "$region" "$id" "echo $payload | base64 -d | gunzip > /root/nt-remote.sh && bash /root/nt-remote.sh $*"
}

# wait_ssm_online <region> <instance-id> <minutes>
wait_ssm_online() {
	local region="$1" id="$2" minutes="$3" ping deadline
	deadline=$((SECONDS + minutes * 60))
	while [ "$SECONDS" -lt "$deadline" ]; do
		ping="$(aws ssm describe-instance-information --region "$region" \
			--filters "Key=InstanceIds,Values=$id" \
			--query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)"
		[ "$ping" = Online ] && return 0
		sleep 10
	done
	return 1
}

# run_ssm_json <region> <instance-id> <command>: like run_ssm, but passes the
# command through a JSON parameters file, so any characters (URLs with & and
# =, quotes) arrive unchanged.
run_ssm_json() {
	local region="$1" id="$2" cmd="$3" cid status pfile
	pfile="$(mktemp)"
	python3 -c 'import json,sys; print(json.dumps({"commands":[sys.argv[1]],"executionTimeout":["900"]}))' "$cmd" >"$pfile"
	cid="$(aws ssm send-command --region "$region" --instance-ids "$id" \
		--document-name AWS-RunShellScript --parameters "file://$pfile" \
		--query Command.CommandId --output text)"
	rm -f "$pfile"
	while :; do
		status="$(aws ssm get-command-invocation --region "$region" --command-id "$cid" --instance-id "$id" \
			--query Status --output text 2>/dev/null || echo Pending)"
		case "$status" in Pending | InProgress | Delayed) sleep 3 ;; *) break ;; esac
	done
	aws ssm get-command-invocation --region "$region" --command-id "$cid" --instance-id "$id" \
		--query StandardOutputContent --output text
	if [ "$status" != Success ]; then
		aws ssm get-command-invocation --region "$region" --command-id "$cid" --instance-id "$id" \
			--query StandardErrorContent --output text >&2
		return 1
	fi
}
