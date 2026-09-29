#!/bin/bash
# Generated audit script - read-only checks only

# Rule: R7
__res=$(grep -E 'iommu=force' /proc/cmdline 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R7' 'grep -E '\''iommu=force'\'' /proc/cmdline' "$__res"

# Rule: R8
__res=$(sysctl kernel.panic_on_oops kernel.randomize_va_space kernel.sysrq kernel.unprivileged_bpf_disabled kernel.perf_event_paranoid 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R8' 'sysctl kernel.panic_on_oops kernel.randomize_va_space kernel.sysrq kernel.unprivileged_bpf_disabled kernel.perf_event_paranoid' "$__res"

# Rule: R9
__res=$(sysctl kernel.dmesg_restrict kernel.kptr_restrict kernel.pid_max kernel.perf_cpu_time_max_percent kernel.perf_event_max_sample_rate 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R9' 'sysctl kernel.dmesg_restrict kernel.kptr_restrict kernel.pid_max kernel.perf_cpu_time_max_percent kernel.perf_event_max_sample_rate' "$__res"

# Rule: R10
__res=$(cat /proc/sys/kernel/modules_disabled 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R10' 'cat /proc/sys/kernel/modules_disabled' "$__res"

# Rule: R11
__res=$(cat /proc/sys/kernel/yama/ptrace_scope 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R11' 'cat /proc/sys/kernel/yama/ptrace_scope' "$__res"

# Rule: R12
__res=$(sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_local net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.accept_source_route 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R12' 'sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_local net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.accept_source_route' "$__res"

# Rule: R13
__res=$(sysctl net.ipv6.conf.default.disable_ipv6 net.ipv6.conf.all.disable_ipv6 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R13' 'sysctl net.ipv6.conf.default.disable_ipv6 net.ipv6.conf.all.disable_ipv6' "$__res"

# Rule: R14
__res=$(sysctl fs.suid_dumpable fs.protected_fifos fs.protected_regular fs.protected_symlinks fs.protected_hardinks 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R14' 'sysctl fs.suid_dumpable fs.protected_fifos fs.protected_regular fs.protected_symlinks fs.protected_hardinks' "$__res"

# Rule: R28
__res=$(findmnt -n --output TARGET,OPTIONS 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R28' 'findmnt -n --output TARGET,OPTIONS' "$__res"

# Rule: R29
__res=$(stat -c '%a %U:%G' /boot 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R29' 'stat -c '\''%a %U:%G'\'' /boot' "$__res"

# Rule: R30
__res=$(getent passwd | grep -v -e 'root' -e 'sync' -e 'shutdown' -e 'halt' 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R30' 'getent passwd | grep -v -e '\''root'\'' -e '\''sync'\'' -e '\''shutdown'\'' -e '\''halt'\''' "$__res"

# Rule: R34
__res=$(getent passwd | awk -F: '$3 >= 100 && $3 <= 999 {print $1, $7}' 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R34' 'getent passwd | awk -F: '\''$3 >= 100 && $3 <= 999 {print $1, $7}'\''' "$__res"

# Rule: R36
__res=$(grep -r 'umask' /etc/profile /etc/profile.d/ 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R36' 'grep -r '\''umask'\'' /etc/profile /etc/profile.d/' "$__res"

# Rule: R38
__res=$(getent group sudogrp 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R38' 'getent group sudogrp' "$__res"

# Rule: R39
__res=$(grep '^Defaults' /etc/sudoers 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R39' 'grep '\''^Defaults'\'' /etc/sudoers' "$__res"

# Rule: R45
__res=$(aa-status 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R45' 'aa-status' "$__res"

# Rule: R46
__res=$(grep '^SELINUX\|^SELINUXTYPE' /etc/selinux/config 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R46' 'grep '\''^SELINUX\|^SELINUXTYPE'\'' /etc/selinux/config' "$__res"

# Rule: R50
__res=$(stat -c '%a %U:%G %n' /etc/shadow /etc/gshadow 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R50' 'stat -c '\''%a %U:%G %n'\'' /etc/shadow /etc/gshadow' "$__res"

# Rule: R53
__res=$(find / -type f \( -nouser -o -nogroup \) -ls 2>/dev/null 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R53' 'find / -type f \( -nouser -o -nogroup \) -ls 2>/dev/null' "$__res"

# Rule: R54
__res=$(find / -type d \( -perm -0002 -a \! -perm -1000 \) -ls 2>/dev/null 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R54' 'find / -type d \( -perm -0002 -a \! -perm -1000 \) -ls 2>/dev/null' "$__res"

# Rule: R56
__res=$(find / -type f -perm /6000 -ls 2>/dev/null 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R56' 'find / -type f -perm /6000 -ls 2>/dev/null' "$__res"

# Rule: R62
__res=$(systemctl list-units --type service --all 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R62' 'systemctl list-units --type service --all' "$__res"

# Rule: R73
__res=$(cat /etc/audit/audit.rules 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R73' 'cat /etc/audit/audit.rules' "$__res"

# Rule: R80
__res=$(ss -tlnp 2>&1 | tr '\n\r\t' '   ' | tr -s ' ' | cut -c1-1000)
printf '%s|%s|%s|%s\n' 'anssi-bp-028-v2' 'R80' 'ss -tlnp' "$__res"

