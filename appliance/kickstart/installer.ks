# Interactive RiverLB installation. Anaconda uses its graphical interface unless
# the operator selects the text-console boot entry (inst.text).
# Storage selection and Begin Installation require the operator's confirmation.
# Never include clearpart, autopart or ignoredisk in this interactive recipe.
%include /run/install/repo/riverlb-common.ks
reboot
