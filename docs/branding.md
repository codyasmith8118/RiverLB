# RiverLB product identity

The product name is **RiverLB**. The appliance is a **RiverLB appliance** and the
application manages traffic through virtual servers, pools and nodes. Use
**RiverRules** for the rule engine, **management portal** for the web interface,
and **Device Certificates** for appliance HTTPS identity. Do not imply another
vendor's compatibility, certification or feature parity.

RiverLB is the primary identity on the browser title, sign-in screen, navigation,
CLI description, packages, installer boot menus, graphical installer and console
setup. The application version and installed build identify the software; they
must not be replaced with an operating-system version. Release readiness is
recorded in the feature inventory and release qualification evidence, rather
than a marketing claim in the interface.

The installer boot menu says **Install RiverLB appliance**. The default entry
checks the remastered media before starting installation. A separate text-console
entry is available under Troubleshooting. The graphical installer uses RiverLB's
river-cut R mark, blue accent and product name. It retains the native
Anaconda forms and their keyboard/accessibility behavior. First boot says
**Welcome to your RiverLB appliance**, then guides the operator through five
numbered steps and ends with the actual management URL.

Normal installer and appliance screens use RiverLB branding without an OS-vendor
subtitle. Keep the distribution's release packages, repository names, signatures,
licenses, EFI vendor directories and checksum provenance intact. The installed
appliance overrides only `NAME` and `PRETTY_NAME` in `/etc/os-release`; `ID`,
`ID_LIKE`, `VERSION_ID` and the vendor's `/usr/lib/os-release` remain intact so
package tools and update compatibility checks still identify the platform.
Console banners and boot entry titles use the RiverLB version and release stage.
The Anaconda product image changes appearance; it does not rename or re-sign
distribution packages or remove license notices.
The ISO filename and artifact manifests remain `riverlb-*` and record both
application and OS versions.

Installer assets live in [appliance/branding](../appliance/branding). The logo is
an SVG using the same mark as the portal's favicon, with a descriptive title and
version and release stage. The mark is a bold white R with a flowing river cut on a
blue rounded square. The sidebar and sign-in page load `web/favicon.svg`
directly so all browser instances share one drawing. Keep the blue-and-white
mark consistent in both light and dark appearances. Installer form controls keep
their native theme. Reuse this identity rather than invent additional logos or slogans.

Review coverage includes the repository README, portal/sign-in/navigation,
installer BIOS and EFI menus (including the FAT image used by firmware),
Anaconda product name/chrome, first-boot prompts, console login banner,
package summaries, CLI help, system provenance and build artifact names.
[Installer branding tests](../tests/appliance/branding.py) check archive content,
menu consistency, preserved boot arguments and product version/stage.

## Changing the version and release stage

Set the application version in `Cargo.toml`, for example `version = "1.1.9"`.
Keep `edition = "2024"`: that field selects Rust's language edition.
Run `cargo check` to refresh `Cargo.lock` after a version change.

Edit [appliance/branding/release-stage](../appliance/branding/release-stage) to one
of `In development`, `Pre-production`, or `Production`. The portal compiles this
label into the application; the installer and installed console/boot branding
use the same source. For example: **RiverLB 1.1.9 · Pre-production**.
Build fresh RPMs and installer media after changing either value. Changing the
label does not replace the release qualification tests.

On an existing appliance with the updated appliance RPM installed, run
`sudo /usr/libexec/riverlb/riverlb-brand-appliance` to refresh console and boot
presentation from the installed RPM version/stage. This leaves networking,
administrator accounts and application configuration alone. Binary-only updates
change the portal's application version; the console identifies the packaged
appliance version until its RPM is updated.

The `product.img` customization follows the
[Anaconda customization documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/customizing_anaconda/index).
On the pinned AlmaLinux 10.2 media, dracut unpacks this archive into `/updates`
and overlays its files at the installer runtime root. The archive therefore
places the stylesheet at `run/install/product/anaconda-gtk.css`, which Anaconda
loads as its high-priority override. A top-level `anaconda-gtk.css` would become
`/anaconda-gtk.css` and remain unused. The sidebar SVG is installed beneath
`/usr/share/anaconda/pixmaps/`, matching the stylesheet's asset URL. Structural
tests check these actual paths; the VM probe reads the product identity using
the installer's own product loader rather than assuming an archive was applied.
The build also inspects the reviewed ISO's `install.img` for the graphical UI,
GTK and Mutter components before advertising graphics. Actual graphical boot,
keyboard/screen-reader interaction and cancellation still require the VM
qualification run; static checks do not certify accessibility or platform support.
