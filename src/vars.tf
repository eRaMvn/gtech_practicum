variable "s3_bucket_name" {
  type    = string
  default = "iam-keeper-state-oesckmpcqeayxfxbxazs"
}
variable "image_tag" {
  type    = string
  default = "6178417f0c52916d280e183711e374cff09211ac"
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
