packer {
  required_plugins {
    qemu = {
      version = "= 1.1.4"
      source  = "github.com/hashicorp/qemu"
    }
  }
}
variable "qemu_binary" {
  type    = string
  default = "qemu-system-x86_64"
}
variable "iso_path" { type = string }
variable "iso_sha256" { type = string }
variable "output_directory" { type = string }
variable "firmware" {
  type    = string
  default = "bios"
  validation {
    condition     = contains(["bios", "uefi"], var.firmware)
    error_message = "Use bios or uefi firmware."
  }
}
variable "efi_code" {
  type    = string
  default = "/usr/share/edk2/ovmf/OVMF_CODE.fd"
}
variable "efi_vars" {
  type    = string
  default = "/usr/share/edk2/ovmf/OVMF_VARS.fd"
}
variable "accelerator" {
  type    = string
  default = "kvm"
  validation {
    condition     = contains(["kvm", "tcg"], var.accelerator)
    error_message = "Use kvm or explicitly select tcg software emulation."
  }
}
source "qemu" "appliance" {
  qemu_binary       = var.qemu_binary
  iso_url           = var.iso_path
  iso_checksum      = "sha256:${var.iso_sha256}"
  output_directory  = var.output_directory
  vm_name           = "riverlb.qcow2"
  format            = "qcow2"
  accelerator       = var.accelerator
  efi_boot          = var.firmware == "uefi"
  efi_firmware_code = var.firmware == "uefi" ? var.efi_code : null
  efi_firmware_vars = var.firmware == "uefi" ? var.efi_vars : null
  efi_drop_efivars  = false
  qemuargs          = [["-cpu", var.accelerator == "kvm" ? "host" : "max"]]
  disk_size         = "16384M"
  disk_interface    = "virtio"
  net_device        = "virtio-net"
  memory            = 4096
  cpus              = 2
  headless          = true
  communicator      = "none"
  shutdown_timeout  = "90m"
  # mkksiso adds inst.ks to the ISO's BIOS/UEFI boot configuration.
  boot_wait    = "10s"
  boot_command = ["<enter>"]
}
build {
  sources = ["source.qemu.appliance"]
}
