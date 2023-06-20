variable "s3_bucket_name" {
  type    = string
  default = "iam-keeper-state-oesckmpcqeayxfxbxazs"
}
variable "image_tag" {
  type    = string
  default = "85e509bc5679ea5fe93ad63e35c19d271e2234bd"
}

variable "account_id" {
  type    = string
  default = "014824332634"
}

variable "iam_keeper_event_handler_role_name" {
  type    = string
  default = "iam_keeper_event_handler_role"
}

variable "iam_keeper_policy_snapshot_role_name" {
  type    = string
  default = "iam_keeper_policy_snapshot_role"
}
