variable "s3_bucket_name" {
  type    = string
  default = "iam-keeper-state-oesckmpcqeayxfxbxazs"
}
variable "image_tag" {
  type    = string
  default = "3ff8cc91d6ab702dfea426c2da76f543682eeab6"
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
