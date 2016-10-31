/^On BSD systems/,/\.$/ {
d
}
/^use_loginclass$/,/^\.TP 18n$/ {
/^\.PD$/!d
}
s/SELinux_Spec? //
/^SELinux_Spec ::=/ {
N
d
}
/^\.SS "SELinux_Spec"/,/^\.SS/{;/^\.SS "[^S][^E][^L]/!d;};
/^[rt][oy][lp]e$/,/^\.TP 18n$/ {
/^\.PD$/!d
}
