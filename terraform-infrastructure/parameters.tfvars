# Stack settings

# General information
team = "dev2" #(NOTE: ensure team name is less than 8 characters)
region =  "us-gov-west-1"
aws_account_id = "345088699538" #(NOTE: 12-digit number, that uniquely identifies your AWS account. On your aws console check the navigation bar on the upper right)
aws_profile = "default"
gitops_branch = "OO-v1.7-dev"

# Security information
key_name = "dev-gc-bastion" #(NOTE: this key should be placed in the ~/.ssh folder and will be used to access the bastion host)
bastion_role = "bastion-host-tf-role" #(NOTE: this role is also referenced in terraform.tf)

# Ingress information
istio_dns = "dev2"
istio_cert = "ba95a131-3416-4c2a-8e6d-ddc498acd2b3"
hosted_zone = "overwatchplatform.com"
client_id = "9bc51f8a-4984-4e3a-802d-b088ec12a04a"
client_secret = "OHV8Q~h3RvG.pOkBALV~Kn9TvTOT7HtEu1D_2dxs"

# Autoscaling information
gpu_instance_type = "p2.xlarge" #(NOTE: instance type for GPU instances of cluster)
gpu_group_max = 1
gpu_group_min = 1
gpu_group_default = 1
infrastructure_instance_type = "m5.4xlarge" #(NOTE: instance type for infrastructure-specific workloads)
infrastructure_group_max = 12
infrastructure_group_min = 4
infrastructure_group_default = 4
worker_instance_type = "m5.4xlarge" #(NOTE: instance type for CPU instances of cluster)
worker_group_max = 12
worker_group_min = 1
worker_group_default = 1

# Network information
vpc_id = "vpc-044f9e1d201a2a39b" #(NOTE: This can be found on the VPC details page that you get when selecting your VPC in the VPC section of the AWS console)
vpc_cidr = "10.0.0.0/16"
subnets = [
  "subnet-0007ae3793b1b8636", #(NOTE: This can be found in the Subnets page of the AWS console)
  "subnet-0091d2c71e6745374",
]
subnets_cidr = [
  "10.0.128.0/20",
  "10.0.144.0/20",
]
nonrouteable_subnets = [
  "subnet-0ff18dc8185682ff3",
  "subnet-038417ba4342acca9",
]

#External Application
nbculling = false #true # false in case if you don't want to enable the functionality
velero = false # true # false in case if you don't want to enable the functionality
platform_metadata_bucket_name = "<<s3_bucket_to_store_inbuilt_apps_template/logs>>" # Used for nbculling and velero

#s3 lifecycle rules
apply_lifecycle_rule = true # this will turn the lifecycle rule on or off (applies to velero, nbculling and loki buckets)

# Webhook Channel Configuration
alert_channel_webhook_url = "Add Teams Channel Webhook URL Here"

