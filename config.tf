# S3 Bucket to store Config data
resource "aws_s3_bucket" "config_bucket" {
  bucket = "configlog-bucket-goa"  # Replace with a unique bucket name
}
 
# IAM Role for AWS Config
resource "aws_iam_role" "config_role" {
  name = "aws-config-role"
 
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "config.amazonaws.com"
      }
    }]
  })
}
 
# IAM Policy for AWS Config
resource "aws_iam_role_policy" "config_policy" {
  role = aws_iam_role.config_role.id
 
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "s3:PutObject",
          "s3:GetBucketAcl",
          "s3:ListBucket"
        ],
        Effect   = "Allow",
        Resource = [
          aws_s3_bucket.config_bucket.arn,
          "${aws_s3_bucket.config_bucket.arn}/*"
        ]
      },
      {
        Action = "sns:Publish",
        Effect = "Allow",
        Resource = aws_sns_topic.config_sns_topic.arn  # Limit to specific topic
      },
      {
        Action = "config:Put*",
        Effect = "Allow",
        Resource = "*"
      }
    ]
  })
}

# SNS Topic Subscription using Email
resource "aws_sns_topic_subscription" "config_sns_subscription" {
  topic_arn = aws_sns_topic.config_sns_topic.arn
  protocol  = "email"
  endpoint  = "itcloudoperations@ilios.digital"  # Email address for notifications
}

# AWS Config Recorder
resource "aws_config_configuration_recorder" "config_recorder" {
  name     = "config-recorder"
  role_arn = aws_iam_role.config_role.arn
  recording_group {
    all_supported = true  # Record all supported resources
    include_global_resource_types = true  # Include global resources (like IAM)
  }
}
 
# AWS Config Delivery Channel with SNS integration
resource "aws_config_delivery_channel" "config_channel" {
  name            = "config-delivery-channel"
  s3_bucket_name  = aws_s3_bucket.config_bucket.bucket
  sns_topic_arn   = aws_sns_topic.config_sns_topic.arn  # SNS topic for notifications
}
 
# Ensure the configuration recorder is started
resource "aws_config_configuration_recorder_status" "config_recorder_status" {
  name    = aws_config_configuration_recorder.config_recorder.name
  is_enabled = true
}
 
# AWS SNS Topic for Config Notifications
resource "aws_sns_topic" "config_sns_topic" {
  name = "config-topic"
}
 
# AWS Config Rule: EBS Optimized Instance
resource "aws_config_config_rule" "ebs_optimized_instance" {
  name = "ebs-optimized-instance"
  source {
    owner             = "AWS"
    source_identifier = "EBS_OPTIMIZED_INSTANCE"
  }
}

# AWS Config Rule: EC2 Instance Detailed Monitoring Enabled
resource "aws_config_config_rule" "ec2_instance_detailed_monitoring_enabled" {
  name = "ec2-instance-detailed-monitoring-enabled"
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_DETAILED_MONITORING_ENABLED"
  }
}

# AWS Config Rule: EC2 Instance Multiple ENI Check
resource "aws_config_config_rule" "ec2_instance_multiple_eni_check" {
  name = "ec2-instance-multiple-eni-check"
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_MULTIPLE_ENI_CHECK"
  }
}

# AWS Config Rule: EC2 Instance No Public IP
resource "aws_config_config_rule" "ec2_instance_no_public_ip" {
  name = "ec2-instance-no-public-ip"
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_NO_PUBLIC_IP"
  }
}

# AWS Config Rule: EC2 Volume In Use Check
resource "aws_config_config_rule" "ec2_volume_inuse_check" {
  name = "ec2-volume-inuse-check"
  source {
    owner             = "AWS"
    source_identifier = "EC2_VOLUME_INUSE_CHECK"
  }
}

# AWS Config Rule: EIP Attached
resource "aws_config_config_rule" "eip_attached" {
  name = "eip-attached"
  source {
    owner             = "AWS"
    source_identifier = "EIP_ATTACHED"
  }
}

# AWS Config Rule: RDS Cluster Multi-AZ Enabled
resource "aws_config_config_rule" "rds_cluster_multi_az_enabled" {
  name = "rds-cluster-multi-az-enabled"
  source {
    owner             = "AWS"
    source_identifier = "RDS_CLUSTER_MULTI_AZ_ENABLED"
  }
}

# AWS Config Rule: RDS Enhanced Monitoring Enabled
resource "aws_config_config_rule" "rds_enhanced_monitoring_enabled" {
  name = "rds-enhanced-monitoring-enabled"
  source {
    owner             = "AWS"
    source_identifier = "RDS_ENHANCED_MONITORING_ENABLED"
  }
}

# AWS Config Rule: RDS Instance Deletion Protection Enabled
resource "aws_config_config_rule" "rds_instance_deletion_protection_enabled" {
  name = "rds-instance-deletion-protection-enabled"
  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_DELETION_PROTECTION_ENABLED"
  }
}

# AWS Config Rule: RDS Instance IAM Authentication Enabled
resource "aws_config_config_rule" "rds_instance_iam_authentication_enabled" {
  name = "rds-instance-iam-authentication-enabled"
  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_IAM_AUTHENTICATION_ENABLED"
  }
}

# AWS Config Rule: S3 Bucket Level Public Access Prohibited
resource "aws_config_config_rule" "s3_bucket_level_public_access_prohibited" {
  name = "s3-bucket-level-public-access-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }
}

# AWS Config Rule: S3 Bucket Default Lock Enabled
resource "aws_config_config_rule" "s3_bucket_default_lock_enabled" {
  name = "s3-bucket-default-lock-enabled"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_DEFAULT_LOCK_ENABLED"
  }
}

# AWS Config Rule: S3 Bucket Logging Enabled
resource "aws_config_config_rule" "s3_bucket_logging_enabled" {
  name = "s3-bucket-logging-enabled"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LOGGING_ENABLED"
  }
}

# AWS Config Rule: S3 Bucket Policy Grantee Check
resource "aws_config_config_rule" "s3_bucket_policy_grantee_check" {
  name = "s3-bucket-policy-grantee-check"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_POLICY_GRANTEE_CHECK"
  }
}

# AWS Config Rule: S3 Bucket Public Read Prohibited
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name = "s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}

# AWS Config Rule: S3 Bucket Public Write Prohibited
resource "aws_config_config_rule" "s3_bucket_public_write_prohibited" {
  name = "s3-bucket-public-write-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }
}

# AWS Config Rule: S3 Bucket Replication Enabled
resource "aws_config_config_rule" "s3_bucket_replication_enabled" {
  name = "s3-bucket-replication-enabled"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_REPLICATION_ENABLED"
  }
}

# AWS Config Rule: S3 Bucket Server Side Encryption Enabled
resource "aws_config_config_rule" "s3_bucket_server_side_encryption_enabled" {
  name = "s3-bucket-server-side-encryption-enabled"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }
}

# AWS Config Rule: S3 Bucket Versioning Enabled
resource "aws_config_config_rule" "s3_bucket_versioning_enabled" {
  name = "s3-bucket-versioning-enabled"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }
}

# AWS Config Rule: S3 Default Encryption KMS
resource "aws_config_config_rule" "s3_default_encryption_kms" {
  name = "s3-default-encryption-kms"
  source {
    owner             = "AWS"
    source_identifier = "S3_DEFAULT_ENCRYPTION_KMS"
  }
}

