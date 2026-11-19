output "controlplane_id" {
  description = "Control plane instance ID (use with aws ssm start-session --target)."
  value       = aws_instance.controlplane.id
}

output "controlplane_ip" {
  description = "Control plane private IP (API server endpoint)."
  value       = local.controlplane_ip
}

output "verifier_id" {
  description = "Verifier host instance ID."
  value       = aws_instance.verifier.id
}

output "workers_asg" {
  description = "Worker Auto Scaling group name."
  value       = aws_autoscaling_group.workers.name
}

output "workers_nacl_id" {
  description = "Worker subnet network ACL."
  value       = aws_network_acl.workers.id
}

output "worker_count" {
  description = "Expected number of workers."
  value       = var.worker_count
}
