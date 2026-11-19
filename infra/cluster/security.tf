# Security groups. Nothing is reachable from the internet. Workers accept
# traffic only from the control plane, other workers and (agent port only) the
# verifier. Pod traffic between nodes uses Calico VXLAN (UDP 4789).

resource "aws_security_group" "controlplane" {
  name        = "${var.cluster_name}-controlplane"
  description = "nodetrust control plane"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.cluster_name}-controlplane" }
}

resource "aws_security_group" "workers" {
  name        = "${var.cluster_name}-workers"
  description = "nodetrust workers"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.cluster_name}-workers" }
}

resource "aws_security_group" "verifier" {
  name        = "${var.cluster_name}-verifier"
  description = "nodetrust verifier (no inbound)"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.cluster_name}-verifier" }
}

locals {
  # One entry per inbound rule: target group, source group, protocol, port.
  ingress_rules = {
    cp_api_from_workers   = { sg = aws_security_group.controlplane.id, src = aws_security_group.workers.id, proto = "tcp", port = 6443 }
    cp_api_from_verifier  = { sg = aws_security_group.controlplane.id, src = aws_security_group.verifier.id, proto = "tcp", port = 6443 }
    cp_vxlan_from_workers = { sg = aws_security_group.controlplane.id, src = aws_security_group.workers.id, proto = "udp", port = 4789 }
    cp_typha_from_workers = { sg = aws_security_group.controlplane.id, src = aws_security_group.workers.id, proto = "tcp", port = 5473 }
    w_kubelet_from_cp     = { sg = aws_security_group.workers.id, src = aws_security_group.controlplane.id, proto = "tcp", port = 10250 }
    w_vxlan_from_cp       = { sg = aws_security_group.workers.id, src = aws_security_group.controlplane.id, proto = "udp", port = 4789 }
    w_vxlan_from_workers  = { sg = aws_security_group.workers.id, src = aws_security_group.workers.id, proto = "udp", port = 4789 }
    w_typha_from_cp       = { sg = aws_security_group.workers.id, src = aws_security_group.controlplane.id, proto = "tcp", port = 5473 }
    w_typha_from_workers  = { sg = aws_security_group.workers.id, src = aws_security_group.workers.id, proto = "tcp", port = 5473 }
    w_agent_from_verifier = { sg = aws_security_group.workers.id, src = aws_security_group.verifier.id, proto = "tcp", port = var.agent_port }
  }
}

resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each                     = local.ingress_rules
  security_group_id            = each.value.sg
  referenced_security_group_id = each.value.src
  ip_protocol                  = each.value.proto
  from_port                    = each.value.port
  to_port                      = each.value.port
  description                  = each.key
}

resource "aws_vpc_security_group_egress_rule" "all" {
  for_each = {
    controlplane = aws_security_group.controlplane.id
    workers      = aws_security_group.workers.id
    verifier     = aws_security_group.verifier.id
  }
  security_group_id = each.value
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "all outbound (NAT for images and AWS APIs)"
}
