locals {
  arn_format  = "arn:${data.aws_partition.current.partition}"
}

data "archive_file" "log_exporter" {
  type        = "zip"
  source_file = "${path.module}/lambda/cloudwatch-to-s3.py"
  output_path = "${path.module}/lambda/tmp/cloudwatch-to-s3.zip"
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}


resource "random_string" "random" {
  length  = 8
  special = false
  upper   = false
  number  = false
}

resource "aws_iam_role" "log_exporter" {
  name = "log-exporter-${var.cloudwatch_logs_export_bucket}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "log_exporter" {
  name = "log-exporter-${var.cloudwatch_logs_export_bucket}"
  role = aws_iam_role.log_exporter.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateExportTask",
        "logs:Describe*",
        "logs:ListTagsLogGroup"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Action": [
        "ssm:DescribeParameters",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "ssm:PutParameter"
      ],
      "Resource": "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/log-exporter-last-export/*",
      "Effect": "Allow"
    },
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/log-exporter-*",
      "Effect": "Allow"
    },
    {
        "Sid": "AllowCrossAccountObjectAcc",
        "Effect": "Allow",
        "Action": [
            "s3:PutObject",
            "s3:PutObjectACL"
        ],
        "Resource": "arn:aws:s3:::${var.cloudwatch_logs_export_bucket}/*"
    },
    {
        "Sid": "AllowCrossAccountBucketAcc",
        "Effect": "Allow",
        "Action": [
            "s3:PutBucketAcl",
            "s3:GetBucketAcl"
        ],
        "Resource": "arn:aws:s3:::${var.cloudwatch_logs_export_bucket}"
    }
  ]
}
EOF
}

resource "aws_lambda_function" "log_exporter" {
  filename         = data.archive_file.log_exporter.output_path
  function_name    = "log-exporter-${var.cloudwatch_logs_export_bucket}"
  role             = aws_iam_role.log_exporter.arn
  handler          = "cloudwatch-to-s3.lambda_handler"
  source_code_hash = data.archive_file.log_exporter.output_base64sha256
  timeout          = 300

  runtime = "python3.8"

  environment {
    variables = {
      S3_BUCKET = var.cloudwatch_logs_export_bucket,
      AWS_ACCOUNT = data.aws_caller_identity.current.account_id
    }
  }
   depends_on = [
    aws_iam_role_policy_attachment.lambda_logs,
    aws_cloudwatch_log_group.this,
  ]
}

resource "aws_cloudwatch_event_rule" "log_exporter" {
  name                = "log-exporter-${var.cloudwatch_logs_export_bucket}"
  description         = "Fires periodically to export logs to S3"
  schedule_expression = "rate(4 hours)"
}

resource "aws_cloudwatch_event_target" "log_exporter" {
  rule      = aws_cloudwatch_event_rule.log_exporter.name
  target_id = "log-exporter-${var.cloudwatch_logs_export_bucket}"
  arn       = aws_lambda_function.log_exporter.arn
}

resource "aws_lambda_permission" "log_exporter" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.log_exporter.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.log_exporter.arn
}


# ---------------------------------------------------------------------------------------------------------------------
# CREATE A KMS 
# We can attach KMS to CloudWatch Log.
# ---------------------------------------------------------------------------------------------------------------------
data "aws_iam_policy_document" "kms" {
  statement {
    sid    = "Enable Root User Permissions"
    effect = "Allow"

    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:Tag*",
      "kms:Untag*",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion"
    ]

    #bridgecrew:skip=CKV_AWS_109:This policy applies only to the key it is attached to
    #bridgecrew:skip=CKV_AWS_111:This policy applies only to the key it is attached to
    resources = [
      "*"
    ]

    principals {
      type = "AWS"

      identifiers = [
        "${local.arn_format}:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
    }
  }

  statement {
    sid    = "Allow KMS to CloudWatch Log Group ${var.cloudwatch_logs_export_bucket}"
    effect = "Allow"

    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]

    resources = [
      "*"
    ]

    principals {
      type = "Service"

      identifiers = [
        "logs.${data.aws_region.current.name}.amazonaws.com"
      ]
    }
    condition {
      test = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.cloudwatch_logs_export_bucket}"]
    }
  }
}

resource "aws_kms_key" "kms" {
  description             = "KMS key for ${var.cloudwatch_logs_export_bucket}"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy                  = join("", data.aws_iam_policy_document.kms.*.json)
}

resource "aws_kms_alias" "this" {
  name          = "alias/log-exporter-${var.cloudwatch_logs_export_bucket}"
  target_key_id = aws_kms_key.kms.key_id
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/log-exporter-${var.cloudwatch_logs_export_bucket}"
  retention_in_days = 365
  kms_key_id = aws_kms_key.kms.arn
}

# See also the following AWS managed policy: AWSLambdaBasicExecutionRole
resource "aws_iam_policy" "lambda_logging" {
  name        = "lambda_logging"
  path        = "/"
  description = "IAM policy for logging from a lambda"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*",
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.log_exporter.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}