# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

provider "aws" {
  region = var.region
  #profile = "General-Admin-PS" # Add Profile
}


data "aws_eks_cluster_auth" "cluster_auth" {
  name = module.eks.cluster_name
}


# Filter out local zones, which are not currently supported 
# with managed node groups

data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  cluster_name = "rus-eks-${random_string.suffix.result}"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"

  name = "rus-eks-vpc"

  cidr = "10.0.0.0/16"
  azs  = slice(data.aws_availability_zones.available.names, 0, 2)

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }
}

# Create a network ACL for public subnets
resource "aws_network_acl" "public_nacl" {
  vpc_id = module.vpc.vpc_id
  subnet_ids = module.vpc.public_subnets
}

# Allow HTTP ingress traffic on public NACL
resource "aws_network_acl_rule" "public_http_ingress" {
  network_acl_id = aws_network_acl.public_nacl.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 80
  to_port        = 80
}

# Allow HTTPS ingress traffic on public NACL
resource "aws_network_acl_rule" "public_https_ingress" {
  network_acl_id = aws_network_acl.public_nacl.id
  rule_number    = 200
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

# Allow all outbound traffic on public NACL
resource "aws_network_acl_rule" "public_all_egress" {
  network_acl_id = aws_network_acl.public_nacl.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

# Define the IAM role with the assume role policy document from the existing role
resource "aws_iam_role" "eks_service_role" {
  name               = "RUSServiceRoleForAmazonEKS"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}


# Attach the AmazonEKSClusterPolicy managed policy to the new IAM role
resource "aws_iam_role_policy_attachment" "eks_cluster_policy_attachment" {
  role       = aws_iam_role.eks_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "attach_eks_node_policy_one" {
  role       = module.eks.eks_managed_node_groups["one"].iam_role_name
  policy_arn = "arn:aws:iam::aws:policy/aws-service-role/AWSServiceRoleForAmazonEKSNodegroup"
}

resource "aws_iam_role_policy_attachment" "attach_eks_node_policy_two" {
  role       = module.eks.eks_managed_node_groups["two"].iam_role_name
  policy_arn = "arn:aws:iam::aws:policy/aws-service-role/AWSServiceRoleForAmazonEKSNodegroup"
}

### OIDC config
/*
resource "aws_iam_openid_connect_provider" "cluster" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = []
  url             = module.eks.cluster_oidc_issuer_url
}
*/


########################## RDS ###################################


module "RDS" {
  source = "terraform-aws-modules/rds/aws"
  depends_on = [module.vpc]

  identifier = "demodb"

  engine            = "postgres"
  # DB option group
  engine_version    = "16.3"
  instance_class    = "db.t4g.micro"
  allocated_storage = 5
  storage_type = "standard"

  db_name  = "demodb"
  username = "ruslan"
  port     = "3306"

  iam_database_authentication_enabled = true



  # Enhanced Monitoring - see example for details on how to create the role
  # by yourself, in case you don't want to create it automatically
  # monitoring_interval    = "30"
  # monitoring_role_name   = "MyRDSMonitoringRole"
  create_monitoring_role = false

  tags = {
    Owner       = "ruslan"
    Environment = "dev"
  }

  # DB subnet group
  create_db_subnet_group  = true
  #vpc_security_group_ids  = [module.eks.cluster_security_group_id]

  # DB parameter group
  family = "postgres16"

  

  # Database Deletion Protection
  deletion_protection = false
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.29.0"

  cluster_name    = local.cluster_name
  cluster_version = "1.31"

  create_iam_role = false
  iam_role_arn = aws_iam_role.eks_service_role.arn  # Set the cluster role ARN

  cluster_endpoint_public_access           = true
  enable_cluster_creator_admin_permissions = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_upgrade_policy = {  
    support_type = "STANDARD"  # Set to STANDARD or EXTENDED as needed
  }
  
  
  eks_managed_node_group_defaults = {
    ami_type = "AL2_x86_64"
    #node_role_arn = data.aws_iam_role.eks_node_group_service_role.arn

  }
  eks_managed_node_groups = {
    one = {
      name = "node-group-1"
      #node_role_arn = data.aws_iam_role.eks_node_group_service_role.arn # Use the existing role

      instance_types = ["t2.micro"]

      min_size     = 1
      max_size     = 2
      desired_size = 2

    }

    two = {
      name = "node-group-2"
      #node_role_arn = data.aws_iam_role.eks_node_group_service_role.arn # Use the existing role
      
      instance_types = ["t2.micro"]

      min_size     = 1
      max_size     = 2
      desired_size = 1
    }
  }
  /*
  cluster_addons = {
    
    aws-ebs-csi-driver = {
      service_account_role_arn = module.irsa-ebs-csi.iam_role_arn
    }
  }
  */
}



/*
# https://aws.amazon.com/blogs/containers/amazon-ebs-csi-driver-is-now-generally-available-in-amazon-eks-add-ons/ 
data "aws_iam_policy" "ebs_csi_policy" {
  arn = "arn:aws:iam::985539801924:role/aws-service-role/eks.amazonaws.com/AWSServiceRoleForAmazonEKS"
}

module "irsa-ebs-csi" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version = "5.39.0"

  create_role                   = true
  role_name                     = "Rus-AmazonEKSTFEBSCSIRole-${module.eks.cluster_name}"
  provider_url                  = module.eks.oidc_provider
  role_policy_arns              = [data.aws_iam_policy.ebs_csi_policy.arn]
  oidc_fully_qualified_subjects = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
}
*/

/*
#------------------------
#install aws LoadBalancer

# EKS Cluster Data Sources
data "aws_eks_cluster" "my_cluster" {
  name = module.eks.cluster_name
  depends_on = [module.eks.cluster_name]
}

data "aws_eks_cluster_auth" "my_cluster_auth" {
  name = module.eks.cluster_name
}


# Install the AWS Load Balancer Controller via Helm

resource "kubernetes_config_map" "aws_auth" {
  depends_on = [module.eks]
  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  data = {
    mapRoles = <<EOF
    - rolearn: ${data.aws_iam_role.eks_service_role.arn}
      username: system:node:{{SessionName}}
      groups:
        - system:masters
    EOF
  }
}

# Install the AWS Load Balancer Controller via Helm

provider "kubernetes" {
  config_path = "C:/Users/Ruslan/.kube/config"
  host                   = data.aws_eks_cluster.my_cluster.endpoint
  token                  = data.aws_eks_cluster_auth.my_cluster_auth.token
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.my_cluster.certificate_authority[0].data)
}

provider "helm" {
  kubernetes {
    config_path = "C:/Users/Ruslan/.kube/config"
    host                   = data.aws_eks_cluster.my_cluster.endpoint
    token                  = data.aws_eks_cluster_auth.cluster_auth.token
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  }
}


resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  namespace  = "kube-system"

  timeout    = 600  # Increase timeout to 600 seconds

  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }

  set {
    name  = "serviceAccount.create"
    value = "true"
  }

  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }

  set {
    name  = "region"
    value = "il-central-1"
  }
}

*/
