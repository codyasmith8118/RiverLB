# Proxmox fencing source

`fence_pve.py.in` is the unmodified Proxmox agent from
[ClusterLabs fence-agents v4.16.0](https://github.com/ClusterLabs/fence-agents/blob/v4.16.0/agents/pve/fence_pve.py).
Its SHA-256 is `2285ab56ac41b25690e67e1eb2cfc14910e133bca28d24d328b1d7b96e4ae406`.
The release matches the fencing support library supplied by the appliance OS.

The package build replaces the Python interpreter and support-library placeholders,
then adds the OS vendor's private Python dependency paths before importing pycurl.
It installs the resulting script as `/usr/sbin/fence_pve`. No runtime downloads or
Python package installation are needed.

The agent is distributed under the included GNU GPL v2 license. Keep the source,
license, provenance, and build substitutions with any redistributed appliance.
Other fencing agents and their SDK dependencies come from the OS vendor's signed
RPMs; their licenses and source package references remain in those RPMs.
