resource "aws_s3_bucket" "iam_keeper_bucket" {
  bucket = var.s3_bucket_name
}
