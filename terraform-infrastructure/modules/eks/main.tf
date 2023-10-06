### Define Local Variables ###
locals {
  eks_cluster_name = "${var.team}-eks-cluster"
  oidc_provider    = replace("${aws_eks_cluster.eks_cluster.identity.0.oidc.0.issuer}", "https://", "")
  nbculling        = "${var.nbculling}"
  velero        = "${var.velero}"
  platform_metadata_bucket_name = "${var.platform_metadata_bucket_name}"
  tf_state_bucket = "${var.tf_state_bucket}"
}

### Create EKS Cluster ###
resource "aws_eks_cluster" "eks_cluster" {
  name     = local.eks_cluster_name
  role_arn = aws_iam_role.eks_iam_role.arn
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  version = "1.26"

  vpc_config {
    security_group_ids      = [aws_security_group.eks_cluster_sg.id]
    subnet_ids              = var.private_subnets
    endpoint_private_access = "true"
    endpoint_public_access  = "false"
    public_access_cidrs     = ["0.0.0.0/0"]
  }

  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.AmazonEKSServicePolicy,
  ]

  tags = {
    creator = "terraform",
    owner   = var.team
  }
}

### Create EKS Node Groups ###
# Node group for infrastructure-supporting nodes (i.e., no notebooks)
#TODO: We can create total 6 nodegroups instead of 3, one for each AZ and instanceType pair

resource "aws_eks_node_group" "eks-node-group-infrastructure" {
  cluster_name    = local.eks_cluster_name
  node_group_name = "${local.eks_cluster_name}-infrastructure"
  node_role_arn   = aws_iam_role.eks_worker_iam_role.arn
  subnet_ids      = var.private_subnets
  ami_type        = var.infrastructure_ami_type
  disk_size       = var.infrastructure_disk_size
  instance_types  = [var.infrastructure_instance_type]
  capacity_type   = "ON_DEMAND"

  scaling_config {
    desired_size = var.infrastructure_group_default
    max_size     = var.infrastructure_group_max
    min_size     = var.infrastructure_group_min
  }

 # labels for infrastructure # necessary for later
 # currently not used by configmap jupyter-web-app-config
  labels = {
    Nodegroup = "infrastructure"
  }

  tags = {
    Name = "${local.eks_cluster_name}-default-node-group"
    team = var.team
    "k8s.io/cluster-autoscaler/enabled" = "true"
    "k8s.io/cluster-autoscaler/${local.eks_cluster_name}" = "owned"
  }

  depends_on = [
    aws_eks_cluster.eks_cluster,
    aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy
  ]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size, scaling_config[0].max_size, scaling_config[0].min_size]
  }
}

# Nodegroup for CPU notebooks
resource "aws_eks_node_group" "eks-node-group-workers" {
  cluster_name    = local.eks_cluster_name
  node_group_name = "${local.eks_cluster_name}-workers"
  node_role_arn   = aws_iam_role.eks_worker_iam_role.arn
  subnet_ids      = var.private_subnets
  ami_type        = var.worker_ami_type
  disk_size       = var.worker_disk_size
  instance_types  = [var.worker_instance_type]
  capacity_type   = var.worker_capacity_type

  scaling_config {
    desired_size = var.worker_group_default
    max_size     = var.worker_group_max
    min_size     = var.worker_group_min
  }

#Currently used by configmap jupyter-web-app-config
  taint {
    key     = "workers"
    value   = "Exists"
    effect  = "NO_SCHEDULE"
  }

  labels = {
    Nodegroup = "workers"
  }

  tags = {
    Name = "${local.eks_cluster_name}-default-node-group"
    team = var.team
    "k8s.io/cluster-autoscaler/enabled" = "true"
    "k8s.io/cluster-autoscaler/${local.eks_cluster_name}" = "owned"
  }

  depends_on = [
    aws_eks_cluster.eks_cluster,
    aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy
  ]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size, scaling_config[0].max_size, scaling_config[0].min_size]
  }  
}

# Nodegroup for GPU notebooks
resource "aws_eks_node_group" "eks-node-group-gpus" {
  cluster_name    = local.eks_cluster_name
  node_group_name = "${local.eks_cluster_name}-gpus"
  node_role_arn   = aws_iam_role.eks_worker_iam_role.arn
  subnet_ids      = var.private_subnets
  ami_type        = var.gpu_ami_type
  disk_size       = var.gpu_disk_size
  instance_types  = [var.gpu_instance_type]
  capacity_type   = "ON_DEMAND"

  scaling_config {
    desired_size = var.gpu_group_default
    max_size     = var.gpu_group_max
    min_size     = var.gpu_group_min
  }
  
  #taints for GPU to lock only GPU instances
  #Currently used by configmap jupyter-web-app-config
  taint {
    key     = "nvidia.com/gpu"
    value   = "Exists"
    effect  = "NO_SCHEDULE"
  }

  labels = {
    Nodegroup = "workers"
  }

  tags = {
    Name = "${local.eks_cluster_name}-default-node-group"
    team = var.team
    "k8s.io/cluster-autoscaler/enabled" = "true"
    "k8s.io/cluster-autoscaler/${local.eks_cluster_name}" = "owned"
  }

  depends_on = [
    aws_eks_cluster.eks_cluster,
    aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy
  ]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size, scaling_config[0].max_size, scaling_config[0].min_size]
  }
}

### Create EKS Control Plane's IAM Role and policies ###
resource "aws_iam_role" "eks_iam_role" {
  name = "${local.eks_cluster_name}-iam-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "eks.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    Creator = "terraform"
  }

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_iam_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKSServicePolicy" {
  policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.eks_iam_role.name
}

### Create EKS Worker Node IAM Role and Policies ###
resource "aws_iam_role" "eks_worker_iam_role" {
  name = "${local.eks_cluster_name}-worker-iam-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    Creator = "terraform"
  }

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

data "local_file" "route53-policy-file" {
  filename = "modules/eks/route53-policy.json"
}

resource "aws_iam_policy" "route53-policy" {
  name   = "${local.eks_cluster_name}-route53-policy"
  policy = data.local_file.route53-policy-file.content
}

resource "aws_iam_role_policy_attachment" "route53-policy-attachment" {
  policy_arn  = aws_iam_policy.route53-policy.arn
  role        = aws_iam_role.eks_worker_iam_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_worker_iam_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_worker_iam_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_worker_iam_role.name
}

resource "aws_iam_instance_profile" "eks_worker_instance_profile" {
  name = "${local.eks_cluster_name}-eks_worker_instance_profile_name"
  role = aws_iam_role.eks_worker_iam_role.name
}

resource "aws_iam_role_policy_attachment" "AutoScalingFullAccess" {
  policy_arn = "arn:aws-us-gov:iam::aws:policy/AutoScalingFullAccess"
  role       = aws_iam_role.eks_worker_iam_role.name
}

resource "aws_iam_role_policy_attachment" "ElasticLoadBalancingFullAccess" {
  policy_arn = "arn:aws-us-gov:iam::aws:policy/ElasticLoadBalancingFullAccess"
  role       = aws_iam_role.eks_worker_iam_role.name
}

resource "aws_iam_role_policy_attachment" "ElasticFileSystemFullAccess" {
  policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonElasticFileSystemFullAccess"
  role       = aws_iam_role.eks_worker_iam_role.name
}


### Create EKS Control Plane Security Group and Security Group Rules ###
resource "aws_security_group" "eks_cluster_sg" {
  name        = "${local.eks_cluster_name}-sg"
  description = "Cluster communication with worker nodes"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Creator = "terraform"
  }

  lifecycle {
    ignore_changes = [tags]
  }
}

resource "aws_security_group_rule" "eks-cluster-ingress-node-https" {
  description              = "Allow pods to communicate with the cluster API Server"
  cidr_blocks              = ["10.1.3.0/24", "10.1.4.0/24"]
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks_cluster_sg.id
  type                     = "ingress"
}

resource "aws_security_group_rule" "eks-cluster-ingress-workstation-https" {
  description       = "Allow local workstation to communicate with the cluster API Server"
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.eks_cluster_sg.id
  type              = "ingress"
}

resource "aws_security_group_rule" "all-traffic-between-eks-cluster-worker" {
  description               = "allow all traffic between worker and cluster"
  source_security_group_id  = aws_security_group.eks_worker_cluster_sg.id
  from_port                 = 0
  to_port                   = 65535
  protocol                  = "-1"
  security_group_id         = aws_security_group.eks_cluster_sg.id
  type                      = "ingress"
}

resource "aws_security_group_rule" "all-traffic-between-eks-node-worker-cluster" {
  description               = "allow all traffic between worker and cluster"
  source_security_group_id  = aws_security_group.eks_cluster_sg.id
  from_port                 = 0
  to_port                   = 65535
  protocol                  = "-1"
  security_group_id         = aws_security_group.eks_worker_cluster_sg.id
  type                      = "ingress"
}

resource "aws_security_group_rule" "all-traffic-between-eks-node-worker-worker" {
  description               = "allow all traffic between worker and cluster"
  source_security_group_id  = aws_security_group.eks_worker_cluster_sg.id
  from_port                 = 0
  to_port                   = 65535
  protocol                  = "-1"
  security_group_id         = aws_security_group.eks_worker_cluster_sg.id
  type                      = "ingress"
}

resource "aws_security_group_rule" "all-traffic-between-eks-node-cluster-cluster" {
  description               = "allow all traffic between worker and cluster"
  source_security_group_id  = aws_security_group.eks_cluster_sg.id
  from_port                 = 0
  to_port                   = 65535
  protocol                  = "-1"
  security_group_id         = aws_security_group.eks_cluster_sg.id
  type                      = "ingress"
}

# ### Create EKS Worker Node Security Group and Security Group Rules ###
resource "aws_security_group" "eks_worker_cluster_sg" {
  name        = "${local.eks_cluster_name}-worker-sg"
  description = "Security group for all nodes in the cluster"
  vpc_id      = var.vpc_id
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Creator = "terraform"
  }

  lifecycle {
    ignore_changes = [tags]
  }
}

resource "aws_security_group_rule" "eks-worker-cluster-ingress-self" {
  description              = "Allow node to communicate with each other"
  cidr_blocks              = ["10.1.3.0/24", "10.1.4.0/24","10.0.6.0/24","10.0.5.0/24"]
  from_port                = 0
  to_port                  = 65535
  protocol                 = "-1"
  security_group_id        = aws_security_group.eks_worker_cluster_sg.id
  type                     = "ingress"
}

resource "aws_security_group_rule" "eks-worker-cluster-ingress-cluster" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
  cidr_blocks              = ["10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24", "10.1.4.0/24","10.0.6.0/24","10.0.5.0/24"]
  from_port                = 1025
  to_port                  = 65535
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks_worker_cluster_sg.id
  type                     = "ingress"
}

### Create CNI Add-on and OIDC Config ###
# cni enabled
resource "aws_eks_addon" "example" {
  cluster_name = aws_eks_cluster.eks_cluster.name
  addon_name   = "vpc-cni"
}

data "aws_region" "current" {}
# Fetch OIDC provider thumbprint for root CA
data "external" "thumbprint" {
  program = ["./modules/eks/oidc-thumbprint.sh", data.aws_region.current.name]
}

# OIDC config
resource "aws_iam_openid_connect_provider" "cluster" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = concat([data.external.thumbprint.result.thumbprint], var.oidc_thumbprint_list)
  url             = aws_eks_cluster.eks_cluster.identity.0.oidc.0.issuer
}

data "tls_certificate" "cluster" {
  url = aws_eks_cluster.eks_cluster.identity.0.oidc.0.issuer
}

### Create ALB Ingress Controller IAM Role and Policies ###
data "local_file" "alb-policy-file" {
  filename = "modules/eks/alb-policy.json"
}

resource "aws_iam_policy" "alb-ingress-controller-policy" {
  name   = "${local.eks_cluster_name}-alb-policy"
  policy = data.local_file.alb-policy-file.content
}

resource "aws_iam_role" "alb-ingress-controller-role" {
  name = "${local.eks_cluster_name}-alb-iam-role"
  path = "/"

  assume_role_policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${local.oidc_provider}:aud": "sts.amazonaws.com",
                    "${local.oidc_provider}:sub": "system:serviceaccount:kube-system:aws-load-balancer-controller"
                }
            }
        }
    ]
}

  )

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

resource "aws_iam_role_policy_attachment" "alb-ingress-controller" {
  policy_arn  = aws_iam_policy.alb-ingress-controller-policy.arn
  role        = aws_iam_role.alb-ingress-controller-role.name
}

### Create Cluster Autoscaler IAM Role and Policies ###
resource "aws_iam_role" "autoscaler_role" {
  name = "${local.eks_cluster_name}-autoscaler-role"
  path = "/"

  assume_role_policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${local.oidc_provider}:sub": "system:serviceaccount:kube-system:cluster-autoscaler"
                }
            }
        }
    ]
}

  )

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

data "local_file" "autoscaler-policy-file" {
  filename = "modules/eks/autoscaler-trust-policy.json"
}

resource "aws_iam_policy" "cluster_autoscaler_policy" {
  name   = "${local.eks_cluster_name}-autoscaler-policy"
  policy = data.local_file.autoscaler-policy-file.content
}

resource "aws_iam_role_policy_attachment" "autoscaler-policy-attachment" {
  policy_arn  = aws_iam_policy.cluster_autoscaler_policy.arn
  role        = aws_iam_role.autoscaler_role.name
}

### Create Loki IAM Role and Policies ###
data "local_file" "loki-policy-file" {
  filename = "modules/eks/loki-policy.json"
}

resource "aws_iam_policy" "loki-policy" {
  name   = "${local.eks_cluster_name}-loki-policy"
  policy = data.local_file.loki-policy-file.content
}

resource "aws_iam_role" "loki-role" {
  name = "${local.eks_cluster_name}-loki-iam-role"
  path = "/"

  assume_role_policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${local.oidc_provider}:sub": "system:serviceaccount:grafana:edp-loki",
                }
            }
        }
    ]
}

  )

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

resource "aws_iam_role_policy_attachment" "loki-policy-attachment" {
  policy_arn  = aws_iam_policy.loki-policy.arn
  role        = aws_iam_role.loki-role.name
}


# #CODE CHANGED HERE -1
# ### EBS CSI DRIVER ROLE
# data "local_file" "ebs-policy-file" {
#   filename = "modules/eks/ebs-iam-policy.json"
# }

# resource "aws_iam_policy" "ebs-policy" {
#   name   = "${local.eks_cluster_name}-ebs-policy"
#   policy = data.local_file.ebs-policy-file.content
# }

# resource "aws_iam_role" "ebs-role" {
#   name = "${local.eks_cluster_name}-ebs-iam-role"
#   path = "/"

#   assume_role_policy = jsonencode(
#     {
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Effect": "Allow",
#             "Principal": {
#                 "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
#             },
#             "Action": "sts:AssumeRoleWithWebIdentity",
#             "Condition": {
#                 "StringEquals": {
#                     "${local.oidc_provider}:sub": "system:serviceaccount:kube-system:ebs-csi-controller-sa",
#                 }
#             }
#         }
#     ]
# }
#   )
#   lifecycle {
#     ignore_changes = [permissions_boundary]
#   }
# }

# resource "aws_iam_role_policy_attachment" "ebs-policy-attachment" {
#   policy_arn  = aws_iam_policy.ebs-policy.arn
#   role        = aws_iam_role.ebs-role.name
# }
# #CODE CHANGE ENDS HERE 


# Code not present in either version any longer, use in case if needed 

### Role for efs-csi driver
# Code not present here before
# data "local_file" "efs-policy-file" {
#   filename = "modules/eks/efs-iam-policy.json"
# }

# resource "aws_iam_policy" "efs-csi-driver-policy" {
#   name   = "${local.eks_cluster_name}-efs-policy"
#   policy = data.local_file.efs-policy-file.content
# }

# resource "aws_iam_role" "efs-csi-driver-role" {
#   name = "${local.eks_cluster_name}-efs-iam-role"
#   path = "/"

#   assume_role_policy = jsonencode(
#     {
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Effect": "Allow",
#             "Principal": {
#                 "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
#             },
#             "Action": "sts:AssumeRoleWithWebIdentity",
#             "Condition": {
#                 "StringEquals": {
#                     "${local.oidc_provider}:sub": "system:serviceaccount:kube-system:efs-storage",
#                 }
#             }
#         }
#     ]
# }
#   )
#   lifecycle {
#     ignore_changes = [permissions_boundary]
#   }
# }

# resource "aws_iam_role_policy_attachment" "efs-policy-attachment" {
#   policy_arn  = aws_iam_policy.efs-csi-driver-policy.arn
#   role        = aws_iam_role.efs-csi-driver-role.name
# }

# End of code block


### Create EFS File System and Mount Target ###
resource "aws_efs_file_system" "efs_fs" {
  creation_token     = "${local.eks_cluster_name}-efs-usi"
  performance_mode   = "generalPurpose"
  encrypted          = "true"
}

resource "aws_efs_mount_target" "efs_mta" {
  file_system_id     = aws_efs_file_system.efs_fs.id
  subnet_id          = var.private_subnets[0]
  security_groups    = [aws_security_group.efs_sg.id]
}

resource "aws_efs_mount_target" "efs_mtb" {
  file_system_id     = aws_efs_file_system.efs_fs.id
  subnet_id          = var.private_subnets[1]
  security_groups    = [aws_security_group.efs_sg.id]
}

### Create EFS Security Group and Security Group Rules ###
resource "aws_security_group" "efs_sg" {
  name        = "${local.eks_cluster_name}-efs-sg"
  description = "Enable traffic between EFS File System and EKS cluster"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Creator = "terraform"
  }

  lifecycle {
    ignore_changes = [tags]
  }
}

resource "aws_security_group_rule" "efs-sg-inbound" {
  description              = "Allow NFS traffic for CIDR of cluster VPC"
  cidr_blocks              = [var.vpc_cidr]
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  security_group_id        = aws_security_group.efs_sg.id
  type                     = "ingress"
}


### Create EFS-CSI Driver IAM Role and Policies ###
data "local_file" "efs-policy-file" {
  filename = "modules/eks/efs-iam-policy.json"
}

resource "aws_iam_policy" "efs-csi-driver-policy" {
  name   = "${local.eks_cluster_name}-efs-policy"
  policy = data.local_file.efs-policy-file.content
}

resource "aws_iam_role" "efs-csi-driver-role" {
  name = "${local.eks_cluster_name}-efs-iam-role"
  path = "/"

  assume_role_policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${local.oidc_provider}:sub": "system:serviceaccount:kube-system:efs-storage",
                }
            }
        }
    ]
}

  )

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

resource "aws_iam_role_policy_attachment" "efs-policy-attachment" {
  policy_arn  = aws_iam_policy.efs-csi-driver-policy.arn
  role        = aws_iam_role.efs-csi-driver-role.name
}

### Create Kubeflow Profile Controller IAM Role and Policies ###
data "local_file" "profile-controller-policy-file" {
  filename = "modules/eks/profile-controller-policy.json"
}

resource "aws_iam_policy" "kubeflow-profile-controller-policy" {
  name   = "${local.eks_cluster_name}-kubeflow-profile-controller-policy"
  policy = data.local_file.profile-controller-policy-file.content
}

resource "aws_iam_role" "profile-controller-role" {
  name = "${local.eks_cluster_name}-profile-controller-iam-role"
  path = "/"

  assume_role_policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${local.oidc_provider}:aud": "sts.amazonaws.com",
                }
            }
        }
    ]
}

  )

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

resource "aws_iam_role_policy_attachment" "profile-controller-policy-attachment" {
  policy_arn  = aws_iam_policy.kubeflow-profile-controller-policy.arn
  role        = aws_iam_role.profile-controller-role.name
}

### EBS CSI DRIVER ROLE
data "local_file" "ebs-policy-file" {
  filename = "modules/eks/ebs-iam-policy.json"
}

resource "aws_iam_policy" "ebs-policy" {
  name   = "${local.eks_cluster_name}-ebs-policy"
  policy = data.local_file.ebs-policy-file.content
}

resource "aws_iam_role" "ebs-role" {
  name = "${local.eks_cluster_name}-ebs-iam-role"
  path = "/"

  assume_role_policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${local.oidc_provider}:sub": "system:serviceaccount:kube-system:ebs-csi-controller-sa",
                }
            }
        }
    ]
}

  )

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

resource "aws_iam_role_policy_attachment" "ebs-policy-attachment" {
  policy_arn  = aws_iam_policy.ebs-policy.arn
  role        = aws_iam_role.ebs-role.name
}

#### Create IAM resources required for Notebook Culling ####

resource "aws_iam_role" "nbculling_role" {
  count = var.nbculling ? 1 : 0
  name = "${local.eks_cluster_name}-nbculling-role"
  path = "/"

  assume_role_policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${local.oidc_provider}:sub": "system:serviceaccount:nbculling:sa-nbculling",
                    "${local.oidc_provider}:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}

  )

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

data "local_file" "metadata-policy-file" {
  filename = "modules/eks/aicoe-nbculling-policy.json"
}

data "template_file" "metadata-policy-template" {
  template = data.local_file.metadata-policy-file.content
  vars = {
    eks_cluster_name = local.eks_cluster_name
    platform_metadata_bucket_name = local.platform_metadata_bucket_name
  }
}

# Replace the placeholder string with the value of the variable
resource "aws_iam_policy" "cluster_metadata_policy" {
  count = var.nbculling ? 1 : 0
  name   = "${local.eks_cluster_name}-metadata-policy"
  policy = data.template_file.metadata-policy-template.rendered #replace(data.local_file.metadata-policy-file.content,"{{eks_cluster_name}}", local.eks_cluster_name)
}


resource "aws_iam_role_policy_attachment" "metadata-policy-attachment" {
  count = var.nbculling ? 1 : 0
  policy_arn  = aws_iam_policy.cluster_metadata_policy[0].arn
  role        = aws_iam_role.nbculling_role[0].name
}


#### Create IAM resources required for Velero Recovery ####

resource "aws_iam_role" "velero-recovery-role" {
  count = var.velero ? 1 : 0
  name = "${local.eks_cluster_name}-velero-recovery-role"
  path = "/"

  assume_role_policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${local.oidc_provider}:sub": "system:serviceaccount:velero:sa-velero-recovery",
                    "${local.oidc_provider}:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}

  )

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

data "local_file" "velero-recovery-file" {
  filename = "modules/eks/velero-recovery-policy.json"
}

data "template_file" "velero-recovery-template" {
  template = data.local_file.velero-recovery-file.content
  vars = {
    platform_metadata_bucket_name = local.platform_metadata_bucket_name
  }
}

# Replace the placeholder string with the value of the variable
resource "aws_iam_policy" "velero-recovery-policy" {
  count = var.velero ? 1 : 0
  name   = "${local.eks_cluster_name}-velero-recovery-policy" 
  policy = data.template_file.velero-recovery-template.rendered
}


resource "aws_iam_role_policy_attachment" "velero-recovery-policy-attachment" {
  count = var.velero ? 1 : 0
  policy_arn  = aws_iam_policy.velero-recovery-policy[0].arn
  role        = aws_iam_role.velero-recovery-role[0].name
}


#### Create IAM resources required for Velero Backup ####


resource "aws_iam_role" "velero-backup-role" {
  count = var.velero ? 1 : 0
  name = "${local.eks_cluster_name}-velero-backup-role"
  path = "/"

  assume_role_policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${local.oidc_provider}:sub": "system:serviceaccount:velero:sa-velero",
                    "${local.oidc_provider}:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}

  )

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

data "local_file" "velero-backup-file" {
  filename = "modules/eks/velero-backup-policy.json"
}

data "template_file" "velero-backup-template" {
  template = data.local_file.velero-backup-file.content
  vars = {
    eks_cluster_name = local.eks_cluster_name
    platform_metadata_bucket_name = local.platform_metadata_bucket_name
  }
}


# Replace the placeholder string with the value of the variable
resource "aws_iam_policy" "velero-backup-policy" {
  count = var.velero ? 1 : 0
  name   = "${local.eks_cluster_name}-velero-backup-policy" 
  policy = data.template_file.velero-backup-template.rendered #replace(data.local_file.velero-backup-file.content,"{{eks_cluster_name}}", local.eks_cluster_name)
}


resource "aws_iam_role_policy_attachment" "velero-backup-policy-attachment" {
  count = var.velero ? 1 : 0
  policy_arn  = aws_iam_policy.velero-backup-policy[0].arn
  role        = aws_iam_role.velero-backup-role[0].name
}

#### Create IAM resources required for minio ####
resource "aws_iam_role" "minio_role" {
  name = "${local.eks_cluster_name}-minio-role"
  path = "/"

  assume_role_policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${local.oidc_provider}:sub": "system:serviceaccount:cserver-minio:sa-minio",
                    "${local.oidc_provider}:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
  }

  )

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

data "local_file" "minio-policy-file" {
  filename = "modules/eks/aicoe-minio-policy.json"
}

data "template_file" "minio-policy-template" {
  template = data.local_file.minio-policy-file.content
  vars = {
    eks_cluster_name = local.eks_cluster_name
    platform_metadata_bucket_name = local.platform_metadata_bucket_name
  }
}

# Replace the placeholder string with the value of the variable
resource "aws_iam_policy" "minio_policy" {
  name   = "${local.eks_cluster_name}-minio-policy"
  policy = data.template_file.minio-policy-template.rendered 
}


resource "aws_iam_role_policy_attachment" "minio-policy-attachment" {
  policy_arn  = aws_iam_policy.minio_policy.arn
  role        = aws_iam_role.minio_role.name
}
#### Create IAM resources required for grafana ####

resource "aws_iam_role" "grafana_role" {
  name = "${local.eks_cluster_name}-grafana-role"
  path = "/"

  assume_role_policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${local.oidc_provider}:sub": "system:serviceaccount:grafana:sa-grafana",
                    "${local.oidc_provider}:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}

  )

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

data "local_file" "grafana-policy-file" {
  filename = "modules/eks/aicoe-grafana-policy.json"
}

data "template_file" "grafana-policy-template" {
  template = data.local_file.grafana-policy-file.content
  vars = {
    eks_cluster_name = local.eks_cluster_name
    platform_metadata_bucket_name = local.platform_metadata_bucket_name
  }
}

# Replace the placeholder string with the value of the variable
resource "aws_iam_policy" "grafana_policy" {
  name   = "${local.eks_cluster_name}-grafana-policy"
  policy = data.template_file.grafana-policy-template.rendered #replace(data.local_file.grafana-policy-file.content,"{{eks_cluster_name}}", local.eks_cluster_name)
}


resource "aws_iam_role_policy_attachment" "grafana-policy-attachment" {
  policy_arn  = aws_iam_policy.grafana_policy.arn
  role        = aws_iam_role.grafana_role.name
}

#### Create IAM resources required for Prometheus ####
resource "aws_iam_role" "prometheus_role" {
  name = "${local.eks_cluster_name}-prometheus-role"
  path = "/"

  assume_role_policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws-us-gov:iam::${var.aws_account_id}:oidc-provider/${local.oidc_provider}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${local.oidc_provider}:sub": "system:serviceaccount:prometheus:sa-prometheus",
                    "${local.oidc_provider}:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
  }

  )

  lifecycle {
    ignore_changes = [permissions_boundary]
  }
}

data "local_file" "prometheus-policy-file" {
  filename = "modules/eks/aicoe-prometheus-policy.json"
}

data "template_file" "prometheus-policy-template" {
  template = data.local_file.prometheus-policy-file.content
  vars = {
    eks_cluster_name = local.eks_cluster_name
    platform_metadata_bucket_name = local.platform_metadata_bucket_name
  }
}

# Replace the placeholder string with the value of the variable
resource "aws_iam_policy" "prometheus_policy" {
  name   = "${local.eks_cluster_name}-prometheus-policy"
  policy = data.template_file.prometheus-policy-template.rendered 
}



resource "aws_iam_role_policy_attachment" "prometheus-policy-attachment" {
  policy_arn  = aws_iam_policy.prometheus_policy.arn
  role        = aws_iam_role.prometheus_role.name
}

