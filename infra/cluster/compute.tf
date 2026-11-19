locals {
  host_ami = coalesce(var.controlplane_ami, var.worker_ami)

  metadata = {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1          # pods cannot reach instance credentials
  }
}

resource "aws_instance" "controlplane" {
  ami                    = local.host_ami
  instance_type          = var.controlplane_instance_type
  subnet_id              = aws_subnet.controlplane.id
  private_ip             = local.controlplane_ip
  vpc_security_group_ids = [aws_security_group.controlplane.id]
  iam_instance_profile   = aws_iam_instance_profile.host["controlplane"].name

  metadata_options {
    http_endpoint               = local.metadata.http_endpoint
    http_tokens                 = local.metadata.http_tokens
    http_put_response_hop_limit = local.metadata.http_put_response_hop_limit
  }

  user_data = templatefile("${path.module}/templates/controlplane-userdata.sh.tftpl", {
    ca_cert_pem    = trimspace(tls_self_signed_cert.ca.cert_pem)
    ca_key_pem     = trimspace(tls_private_key.ca.private_key_pem)
    token          = local.bootstrap_token
    cp_ip          = local.controlplane_ip
    pod_cidr       = var.pod_cidr
    calico_version = var.calico_version
  })
  user_data_replace_on_change = true

  tags = { Name = "${var.cluster_name}-controlplane", role = "controlplane" }

  depends_on = [aws_route_table_association.private, aws_nat_gateway.this, time_sleep.iam_propagation]
}

resource "aws_instance" "verifier" {
  ami                    = local.host_ami
  instance_type          = var.verifier_instance_type
  subnet_id              = aws_subnet.verifier.id
  vpc_security_group_ids = [aws_security_group.verifier.id]
  iam_instance_profile   = aws_iam_instance_profile.host["verifier"].name

  metadata_options {
    http_endpoint               = local.metadata.http_endpoint
    http_tokens                 = local.metadata.http_tokens
    http_put_response_hop_limit = local.metadata.http_put_response_hop_limit
  }

  # The verifier service is installed by infra/phase4/deploy-verifier.sh.
  # The Kubernetes services and the agent from the golden AMI are not needed
  # on this host.
  user_data = <<-EOF
    #!/bin/bash
    systemctl disable --now kubelet containerd nodetrust-agent
  EOF

  tags = { Name = "${var.cluster_name}-verifier", role = "verifier" }

  depends_on = [aws_route_table_association.private, aws_nat_gateway.this, time_sleep.iam_propagation]
}

resource "aws_launch_template" "workers" {
  name_prefix            = "${var.cluster_name}-workers-"
  image_id               = var.worker_ami
  instance_type          = var.worker_instance_type
  update_default_version = true

  iam_instance_profile {
    name = aws_iam_instance_profile.host["workers"].name
  }

  metadata_options {
    http_endpoint               = local.metadata.http_endpoint
    http_tokens                 = local.metadata.http_tokens
    http_put_response_hop_limit = local.metadata.http_put_response_hop_limit
  }

  network_interfaces {
    device_index    = 0
    security_groups = [aws_security_group.workers.id]

    connection_tracking_specification {
      tcp_established_timeout = var.tcp_established_timeout
    }
  }

  user_data = base64encode(templatefile("${path.module}/templates/worker-userdata.sh.tftpl", {
    ca_cert_b64 = base64encode(tls_self_signed_cert.ca.cert_pem)
    token       = local.bootstrap_token
    cp_ip       = local.controlplane_ip
  }))

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.cluster_name}-worker", role = "worker" }
  }

  tag_specifications {
    resource_type = "volume"
    tags          = { Name = "${var.cluster_name}-worker", role = "worker" }
  }

  depends_on = [time_sleep.iam_propagation]
}

resource "aws_autoscaling_group" "workers" {
  name                  = "${var.cluster_name}-workers"
  min_size              = var.worker_count
  max_size              = var.worker_count
  desired_capacity      = var.worker_count
  vpc_zone_identifier   = [aws_subnet.workers.id]
  max_instance_lifetime = var.max_instance_lifetime
  health_check_type     = "EC2"

  launch_template {
    id      = aws_launch_template.workers.id
    version = aws_launch_template.workers.latest_version
  }

  tag {
    key                 = "project"
    value               = "nodetrust"
    propagate_at_launch = true
  }

  # Workers wait for the API server themselves; starting them after the
  # control plane instance exists keeps the join retries short.
  depends_on = [aws_instance.controlplane, aws_route_table_association.private]
}
