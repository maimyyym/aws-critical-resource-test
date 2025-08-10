# AWS Foundational Security Best Practices違反を含むTerraformコード
# 重大(Critical)と高(High)重要度の違反を中心に構成

# 1. [EC2.1] EBSスナップショットがパブリック - Critical違反
resource "aws_ebs_snapshot" "app_backup" {
  volume_id = aws_ebs_volume.app_data.id

  # Critical違反: スナップショットをパブリックに設定
  # (create_volume_permission)
}

resource "aws_snapshot_create_volume_permission" "app_backup_public" {
  snapshot_id = aws_ebs_snapshot.app_backup.id
  account_id  = "all"  # Critical違反: パブリックアクセス許可
}

# 2. [CodeBuild.1][CodeBuild.2] CodeBuildでの認証情報漏洩 - Critical違反
resource "aws_codebuild_project" "app_build" {
  name          = "app-build-project"
  service_role  = aws_iam_role.codebuild_role.arn

  source {
    type     = "BITBUCKET"
    # Critical違反: URLに認証情報を含む
    location = "https://user:password123@bitbucket.org/company/repo.git"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:5.0"
    type         = "LINUX_CONTAINER"

    # Critical違反: 環境変数に平文でクリアテキストの認証情報
    environment_variable {
      name  = "DB_PASSWORD"
      value = "supersecretpassword123"  # Critical違反
    }

    environment_variable {
      name  = "API_KEY"  
      value = "ak_live_1234567890abcdef"  # Critical違反
    }
  }

  artifacts {
    type = "NO_ARTIFACTS"
  }
}

# 4. [DocumentDB.3] DocumentDBスナップショットがパブリック - Critical違反
resource "aws_docdb_cluster_snapshot" "app_backup" {
  db_cluster_identifier          = aws_docdb_cluster.app_cluster.id
  db_cluster_snapshot_identifier = "app-cluster-snapshot"
}

# Critical違反: 手動スナップショットをパブリックに共有
# (通常はaws_docdb_cluster_snapshot_attributeで設定)

# 5. [EC2.19] セキュリティグループでリスクの高いポートへの無制限アクセス - Critical違反
resource "aws_security_group" "risky_ports_sg" {
  description = "Risky ports security group"
  vpc_id          = aws_vpc.main.id

  # Critical違反: 危険なポートへの全世界アクセス許可
  ingress {
    from_port   = 20    # FTP Data
    to_port     = 21    # FTP Control
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Critical違反
  }

  ingress {
    from_port   = 23    # Telnet
    to_port     = 23
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Critical違反
  }

  ingress {
    from_port   = 135   # RPC Endpoint Mapper
    to_port     = 135
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Critical違反
  }

  ingress {
    from_port   = 445   # SMB
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Critical違反
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 6. [EMR.2] EMRブロックパブリックアクセスが無効 - Critical違反
# aws_emr_block_public_access_configurationリソースが存在しない
# または以下の設定:
resource "aws_emr_block_public_access_configuration" "example" {
  # Critical違反: パブリックアクセスブロックが無効
  block_public_security_group_rules = false
}

# 7. [ES.2] Elasticsearchドメインがパブリック - Critical違反
resource "aws_elasticsearch_domain" "app_search" {
  domain_name           = "app-search-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
  }

  # Critical違反: VPC設定なし = パブリックアクセス
  # vpc_options ブロックが存在しない

  ebs_options {
    ebs_enabled = true
    volume_size = 20
  }
}

# 8. [CloudTrail.6] CloudTrail用S3バケットがパブリック - Critical違反
resource "aws_s3_bucket" "cloudtrail_public" {
  bucket = "my-company-cloudtrail-public-bucket"
}

resource "aws_s3_bucket_policy" "cloudtrail_public_policy" {
  bucket = aws_s3_bucket.cloudtrail_public.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"  # Critical違反: パブリックアクセス
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.cloudtrail_public.arn,
          "${aws_s3_bucket.cloudtrail_public.arn}/*"
        ]
      }
    ]
  })
}

# 9. [Config.1] AWS Configが無効 - Critical違反
# aws_config_configuration_recorderリソースが存在しない

# 10. [GuardDuty.1] GuardDutyが無効 - High違反  
# aws_guardduty_detectorリソースが存在しない

# 11. [CloudTrail.1] CloudTrailマルチリージョン追跡なし - High違反
resource "aws_cloudtrail" "single_region_trail" {
  name           = "single-region-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_public.id

  # High違反: マルチリージョン追跡が無効
  is_multi_region_trail = false

  # 管理イベントを含めない設定も違反
  event_selector {
    read_write_type                 = "ReadOnly"  # High違反: 書き込みイベント除外
    include_management_events       = false       # High違反: 管理イベント除外
  }
}

# 12. [EC2.2] デフォルトセキュリティグループがトラフィック許可 - High違反
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  # High違反: デフォルトSGでインバウンド許可
  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
  }

  # High違反: デフォルトSGでアウトバウンド許可
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 13. [EC2.8] EC2インスタンスでIMDSv2未使用 - High違反
resource "aws_instance" "app_server" {
  ami           = "ami-0c55b159cbfafe1d0"
  instance_type = "t3.micro"

  # High違反: IMDSv1のみ許可
  metadata_options {
    http_tokens = "optional"  # High違反: IMDSv2必須でない
    http_endpoint = "enabled"
  }
}

# 14. [EC2.9] EC2インスタンスにパブリックIPv4 - High違反
resource "aws_instance" "public_server" {
  ami           = "ami-0c55b159cbfafe1d0"
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public.id

  # High違反: パブリックIPアドレス自動割り当て
  associate_public_ip_address = true
}

# 15. [ECS.1] ECSタスク定義でネットワークモード・ユーザー設定不適切 - High違反
resource "aws_ecs_task_definition" "insecure_task" {
  family = "insecure-task"

  # High違反: hostネットワークモード使用
  network_mode = "host"

  container_definitions = jsonencode([
    {
      name  = "app-container"
      image = "nginx:latest"
      
      # High違反: 特権コンテナ
      privileged = true
      
      # High違反: rootユーザーで実行（user指定なし）
      
      memory = 512
      essential = true
    }
  ])

  requires_compatibilities = ["EC2"]
  cpu                      = 256
  memory                   = 512
}

# 16. [ECR.1] ECRでイメージスキャンが無効 - High違反
resource "aws_ecr_repository" "app_repo" {
  name = "app-repository"

  # High違反: イメージスキャンが無効
  image_scanning_configuration {
    scan_on_push = false
  }
}

# 18. [AutoScaling.3] Auto Scalingでインスタンスメタデータ設定不備 - High違反
resource "aws_launch_configuration" "app_lc" {
  name            = "app-launch-config"
  image_id        = "ami-0c55b159cbfafe1d0"
  instance_type   = "t3.micro"

  # High違反: metadata_optionsの設定なし
  # IMDSv2が必須になっていない
}

# 19. [AutoScaling.5] Auto ScalingでパブリックIP割り当て - High違反
resource "aws_launch_configuration" "public_lc" {
  name            = "public-launch-config"
  image_id        = "ami-0c55b159cbfafe1d0"
  instance_type   = "t3.micro"

  # High違反: パブリックIP自動割り当て
  associate_public_ip_address = true
}

# 20. [EC2.25] EC2起動テンプレートでパブリックIP設定 - High違反
resource "aws_launch_template" "app_template" {
  name_prefix   = "app-template"
  image_id      = "ami-0c55b159cbfafe1d0"
  instance_type = "t3.micro"

  network_interfaces {
    # High違反: パブリックIP自動割り当て
    associate_public_ip_address = true
    delete_on_termination       = true
  }
}

# サポートリソース
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "private_1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "private_2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-west-2b"
}

resource "aws_ebs_volume" "app_data" {
  availability_zone = "us-west-2a"
  size              = 40
}

resource "aws_docdb_cluster" "app_cluster" {
  cluster_identifier = "app-cluster"
  engine            = "docdb"
  master_username   = "username"
  master_password   = "password"
}

resource "aws_iam_role" "codebuild_role" {
  name = "codebuild-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role" "eks_cluster_role" {
  name = "eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}