resource "openstack_networking_secgroup_v2" "m2_wide_open_sg" {
  name        = local.wide_open_sg_name
  description = "INSECURE demo SG: ingress from 0.0.0.0/0"
}

resource "openstack_networking_secgroup_rule_v2" "m2_ssh_anywhere" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.m2_wide_open_sg.id
}

resource "openstack_networking_secgroup_rule_v2" "m2_rdp_anywhere" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 3389
  port_range_max    = 3389
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.m2_wide_open_sg.id
}

resource "openstack_networking_secgroup_rule_v2" "m2_all_anywhere" {
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.m2_wide_open_sg.id
}
