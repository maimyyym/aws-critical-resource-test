# CIS AWS Foundations Benchmark違反を含むTerraformコード例
# Inspector Code SecurityのIaCスキャンによる検証用

# 1. [EC2.13][EC2.21] SSH (Port 22) を0.0.0.0/0から許可 - Critical
resource "aws_security_group" "web_server_sg" {
  vpc_id          = aws_vpc.main.id

  # Critical違反: SSH全開放
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # CIS違反: SSH全世界公開
  }

  # Critical違反: RDP全開放
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # CIS違反: RDP全世界公開
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 2. [S3.1][S3.8] S3バケットのパブリックアクセス許可 - Critical
resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-company-sensitive-data-bucket-2025"
}

# Critical違反: パブリックアクセスブロック設定なし
# aws_s3_bucket_public_access_block リソースが存在しない

# Critical違反: バケットポリシーでパブリック読み取り許可
resource "aws_s3_bucket_policy" "data_bucket_policy" {
  bucket = aws_s3_bucket.data_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"  # CIS違反: 全世界からアクセス可能
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.data_bucket.arn,
          "${aws_s3_bucket.data_bucket.arn}/*"
        ]
      }
    ]
  })
}

# 3. [S3.5] S3バケットのSSL強制なし - Critical
# aws_s3_bucket_policy でSSL強制の設定が不足

# 4. [RDS.2] RDSインスタンスのパブリックアクセス - Critical
resource "aws_db_instance" "main_database" {
  identifier = "main-production-db"
  
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  
  allocated_storage = 20
  
  db_name  = "maindb"
  username = "admin"
  password = "password123"  # セキュリティ問題: ハードコードされたパスワード
  
  publicly_accessible = true  # CIS違反: パブリックアクセス許可
  
  # Critical違反: 暗号化が無効
  storage_encrypted = false  # CIS違反: [RDS.3]
  
  skip_final_snapshot = true
}

# 5. [EFS.1] EFS暗号化なし - Critical
resource "aws_efs_file_system" "app_storage" {
  creation_token = "app-file-storage"
  
  # Critical違反: 暗号化が無効
  encrypted = false  # CIS違反: 保存時暗号化なし
}

# 6. [EC2.7] EBSデフォルト暗号化が無効 - Critical
# aws_ebs_encryption_by_default リソースが存在しない

# 7. [KMS.4] KMSキーローテーションが無効 - High
resource "aws_kms_key" "app_key" {
  description             = "Application encryption key"
  deletion_window_in_days = 7
  
  # Critical違反: キーローテーションが無効
  enable_key_rotation = false  # CIS違反: 自動ローテーションなし
}

# 8. [IAM.1] 過度な権限のIAMポリシー - Critical
resource "aws_iam_policy" "admin_policy" {
  name = "ApplicationAdminPolicy"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"      # CIS違反: 全権限許可
        Resource = "*"    # CIS違反: 全リソース許可
      }
    ]
  })
}

# 9. [EC2.6] VPCフローログなし - High
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
}

# Critical違反: VPCフローログが設定されていない
# aws_flow_log リソースが存在しない

# 10. [CloudTrail.1][CloudTrail.2] CloudTrail設定不備 - Critical
resource "aws_cloudtrail" "main_trail" {
  name           = "main-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_bucket.id
  
  # Critical違反: マルチリージョン追跡が無効
  is_multi_region_trail = false  # CIS違反
  
  # Critical違反: 暗号化が無効
  # kms_key_id が設定されていない
  
  # Critical違反: ログファイル検証が無効
  enable_log_file_validation = false  # CIS違反
}

# CloudTrail用バケット（これも違反）
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = "my-company-cloudtrail-logs-2025"
  force_destroy = true
}

# Critical違反: CloudTrailバケットのパブリックアクセス制御なし
# aws_s3_bucket_public_access_block が存在しない