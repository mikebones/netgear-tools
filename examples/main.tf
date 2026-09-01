terraform {
  required_providers {
    pr60x = {
      source = "local/mikebones/pr60x"
    }
  }
}

# Password comes from PR60X_PASSWORD. Endpoint defaults to https://192.168.1.1
# and username to admin, so this block can usually stay empty.
provider "pr60x" {}

# --- Read-only: audit what the router currently exposes ---------------------

data "pr60x_device_info" "this" {}

data "pr60x_service_profiles" "all" {}

data "pr60x_port_forwarding_rules" "all" {}

output "device" {
  description = "Model, firmware and which management plane owns the device."
  value = {
    model           = data.pr60x_device_info.this.product_id
    firmware        = data.pr60x_device_info.this.firmware_version
    management_mode = data.pr60x_device_info.this.management_mode
    insight_status  = data.pr60x_device_info.this.insight_status
    temperature_c   = data.pr60x_device_info.this.temperature_celsius
  }
}

# The authoritative answer to "what is reachable from the internet?" - which
# lives nowhere else outside the appliance itself.
output "internet_exposed" {
  description = "Every enabled WAN-to-LAN forward, as service -> internal host."
  value = [
    for r in data.pr60x_port_forwarding_rules.all.rules : {
      id       = r.id
      external = r.external_service
      internal = r.internal_service
      to       = r.dest_ip_address
      from     = r.src_ip_address
    } if r.enabled
  ]
}

# --- Managed resources ------------------------------------------------------
#
# Commented out until scripts/roundtrip.py has confirmed the write payload
# shape - see the write-shape note in internal/provider/client.go. Every read
# path above is verified; the create/update/delete paths are inferred.
#
# A forward is always two resources: the service profile defines the ports,
# the rule points it at a host. Referencing .name rather than hardcoding the
# string is what makes Terraform order them correctly.

# resource "pr60x_service_profile" "wireguard_kube" {
#   name       = "WG-KUBE"
#   proto      = "udp"
#   start_port = 51226
#   end_port   = 51226
# }
#
# resource "pr60x_port_forwarding_rule" "wireguard_kube" {
#   external_service = pr60x_service_profile.wireguard_kube.name
#   internal_service = pr60x_service_profile.wireguard_kube.name
#   dest_ip_address  = "192.168.1.72"
#   enabled          = true
# }
