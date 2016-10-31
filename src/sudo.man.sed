/^\\fR0\\fR$/ {
N
s/^\\fR0\\fR\nminutes\.$/unlimited./
}
/^\[\\fB\\-a\\fR\\ \\fIauth_type\\fR/d
/^\\fB\\-a\\fR \\fItype\\fR$/,/^\.TP 12n$/ {
/^\.PD$/!d
}
/^\[\\fB\\-c\\fR\\ \\fIclass\\fR/d
/^\\fB\\-c\\fR \\fIclass\\fR$/,/^\.TP 12n$/ {
/^\.PD$/!d
}
/^login_cap(3),$/d
/^BSD login class$/ {
N
N
/^BSD login class\n\.TP 4n\n\\fBo\\fR$/d
}
/^\[\\fB\\-[rt]\\fR\\ \\fI[rt][oy][lp]e\\fR/d
/^\\fB\\-[rt]\\fR \\fI[rt][oy][lp]e\\fR$/,/^\.TP 12n$/ {
/^\.PD$/!d
}
/^SELinux role and type$/ {
N
N
/^SELinux role and type\n\.TP 4n\n\\fBo\\fR$/d
}
/^Solaris project$/ {
N
N
N
N
N
/^Solaris project\n\.TP 4n\n\\fBo\\fR\nSolaris privileges\n\.TP 4n\n\\fBo\\fR$/d
}
