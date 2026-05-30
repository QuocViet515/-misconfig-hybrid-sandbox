data "openstack_identity_role_v3" "m3_demo_role" {
  name = var.demo_role
}

resource "openstack_identity_project_v3" "m3_overpriv_project" {
  name = local.overpriv_project
}

resource "openstack_identity_user_v3" "m3_overpriv_user" {
  name               = local.overpriv_user
  default_project_id = openstack_identity_project_v3.m3_overpriv_project.id
  password           = var.demo_password
}

resource "openstack_identity_role_assignment_v3" "m3_admin_assignment" {
  user_id    = openstack_identity_user_v3.m3_overpriv_user.id
  project_id = openstack_identity_project_v3.m3_overpriv_project.id
  role_id    = data.openstack_identity_role_v3.m3_demo_role.id
}
