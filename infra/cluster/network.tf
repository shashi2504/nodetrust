# One VPC in one AZ. The NAT gateway sits in the public subnet; the control
# plane, the verifier and the workers each get their own private subnet.
# The other subnets share one network ACL that the trust controller adds
# per-node quarantine denies to (blueprint 8.3, Phase 5).

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  az = coalesce(var.availability_zone, data.aws_availability_zones.available.names[0])

  public_cidr       = cidrsubnet(var.vpc_cidr, 8, 0) # 10.42.0.0/24
  controlplane_cidr = cidrsubnet(var.vpc_cidr, 8, 1) # 10.42.1.0/24
  verifier_cidr     = cidrsubnet(var.vpc_cidr, 8, 2) # 10.42.2.0/24
  workers_cidr      = cidrsubnet(var.vpc_cidr, 4, 1) # 10.42.16.0/20

  controlplane_ip = cidrhost(local.controlplane_cidr, 10)
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.cluster_name }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = var.cluster_name }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = local.public_cidr
  availability_zone = local.az
  tags              = { Name = "${var.cluster_name}-public" }
}

resource "aws_subnet" "controlplane" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = local.controlplane_cidr
  availability_zone = local.az
  tags              = { Name = "${var.cluster_name}-controlplane" }
}

resource "aws_subnet" "verifier" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = local.verifier_cidr
  availability_zone = local.az
  tags              = { Name = "${var.cluster_name}-verifier" }
}

resource "aws_subnet" "workers" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = local.workers_cidr
  availability_zone = local.az
  tags              = { Name = "${var.cluster_name}-workers" }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${var.cluster_name}-nat" }
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
  tags          = { Name = var.cluster_name }
  depends_on    = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = "${var.cluster_name}-public" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this.id
  }
  tags = { Name = "${var.cluster_name}-private" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  for_each = {
    controlplane = aws_subnet.controlplane.id
    verifier     = aws_subnet.verifier.id
    workers      = aws_subnet.workers.id
  }
  subnet_id      = each.value
  route_table_id = aws_route_table.private.id
}

# Worker subnet NACL: allow everything at rule 1000.
resource "aws_network_acl" "workers" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = [aws_subnet.workers.id]

  ingress {
    rule_no    = 1000
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    rule_no    = 1000
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.cluster_name}-workers" }
}

# Network ACL of the public (NAT), control plane and verifier subnets:
# allow everything at rule 1000 and leave 100-999 for the controller's
# quarantine denies. An ACL rule matches the remote address, so a deny for a
# worker's IP works here ("inbound from it", "outbound to it"), not on the
# worker's own subnet (pkg/provider/aws/containment.go).
resource "aws_network_acl" "infra" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = [aws_subnet.public.id, aws_subnet.controlplane.id, aws_subnet.verifier.id]

  ingress {
    rule_no    = 1000
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    rule_no    = 1000
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.cluster_name}-infra" }

  # The controller adds and keeps deny entries at run time.
  lifecycle {
    ignore_changes = [ingress, egress]
  }
}
