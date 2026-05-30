resource "openstack_identity_project_v3" "m3_overpriv_project" {
  name = local.overpriv_project
}

resource "openstack_identity_user_v3" "m3_overpriv_user" {
  name               = local.overpriv_user
  default_project_id = openstack_identity_project_v3.m3_overpriv_project.id
  password           = var.demo_password
}

