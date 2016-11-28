:again
/^\.TP 18n$/ {
N
bagain
}
/^\.SS "SELinux_Spec"/,/^\.SS "[^S]/{;/^\.SS "[^S][^o][^l]/!d;};
/^On BSD systems/,/\.$/d
/^\.TP 18n\nuse_loginclass$/,/^by default\./d
s/Solaris_Priv_Spec? //
/^Solaris_Priv_Spec ::=/ {
N
d
}
/^\.TP 18n\n\(limit\)*privs$/,/^is built on Solaris 10 or higher\./d
/^On Solaris 10/,/^\.[sP][pP]/d
s/SELinux_Spec? //
/^SELinux_Spec ::=/ {
N
d
}
/^\.TP 18n\n[rt][oy][lp]e$/,/^is built with SELinux support\.$/d
