output "m2_wide_open_sg_name" {
  value = openstack_networking_secgroup_v2.m2_wide_open_sg.name
}

output "m2_wide_open_sg_id" {
  value = openstack_networking_secgroup_v2.m2_wide_open_sg.id
}

output "m3_overpriv_project_name" {
  value = openstack_identity_project_v3.m3_overpriv_project.name
}

output "m3_overpriv_project_id" {
  value = openstack_identity_project_v3.m3_overpriv_project.id
}

output "m3_overpriv_user_name" {
  value = openstack_identity_user_v3.m3_overpriv_user.name
}

output "m3_overpriv_user_id" {
  value = openstack_identity_user_v3.m3_overpriv_user.id
}

output "summary" {
  value = <<-EOT
    OpenStack Terraform lab deployed.
    - M2 security group: ${openstack_networking_secgroup_v2.m2_wide_open_sg.name}
    - M3 project: ${openstack_identity_project_v3.m3_overpriv_project.name}
    - M3 user: ${openstack_identity_user_v3.m3_overpriv_user.name}
    - M1 object storage: optional and not modeled in this Terraform stack
  EOT
}
