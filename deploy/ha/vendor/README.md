# Fencing dependencies

The appliance includes the OS vendor's signed fencing RPMs and SDK dependencies.
Two integrations need additional packaging:

- [Proxmox](fence-agents/README.md) uses a pinned upstream agent because the OS
  does not package it.
- OpenStack uses the vendor agent through `fence_riverlb_openstack`, with a private
  Nova/Keystone SDK. The vendor agent omits these optional Python dependencies.
  `openstack-requirements.txt` locks every distribution and wheel hash. Builds
  install these wheels into `/usr/lib/riverlb/fencing/openstack`; they do not
  change the system Python packages. The installed wheel metadata includes each
  dependency's license. Package tests import the SDK in a disconnected container.

The lock targets Python 3.12 on Linux x86_64, matching this appliance's package
target. To update it, resolve the complete wheel closure in the pinned builder
image, inspect the versions and licenses, generate a SHA-256 for every wheel, and
rerun the offline package and fencing tests. Do not remove the hash checks or
allow source builds as a workaround for a changed dependency.
