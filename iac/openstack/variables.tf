variable "project_prefix" {
  description = "Prefix for all OpenStack demo resources"
  type        = string
  default     = "threat-demo"
}

variable "demo_password" {
  description = "Password for the intentionally overprivileged demo user"
  type        = string
  default     = "ChangeMe123!"
  sensitive   = true
}

variable "demo_role" {
  description = "OpenStack role name to assign to the demo user"
  type        = string
  default     = "admin"
}

variable "include_object_storage" {
  description = "Reserved flag for the optional M1 object storage scenario"
  type        = bool
  default     = false
}

locals {
  wide_open_sg_name = "${var.project_prefix}-m2-wide-open-sg"
  overpriv_project  = "${var.project_prefix}-m3-overpriv-project"
  overpriv_user     = "${var.project_prefix}-m3-overpriv-user"
  public_container  = "${var.project_prefix}-m1-public-container"
}
