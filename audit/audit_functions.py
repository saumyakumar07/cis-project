def is_root_login_disabled(audit) -> bool:
    try:
        cmd = "grep -i '^PermitRootLogin' /etc/ssh/sshd_config"
        stdout, stderr = audit._shellexec(cmd)

        if stderr:
            raise Exception(f"Error checking sshd_config on {audit.hostname}: {stderr}")

        if "PermitRootLogin no" in stdout:
            return True
        elif "PermitRootLogin" in stdout:
            return False
        else:
            return False
    except Exception as e:
        return str(e)


def audit_events_for_unsuccessful_file_access_attempts(audit) -> int:
    try:
        state = 0
        cmd1 = R"grep -h access /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep access"

        expected_file_output = [
            "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access",
            "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access",
            "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access",
            "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access",
        ]
        expected_auditctl_output = [
            "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access",
            "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access",
            "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access",
            "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access",
        ]

        r1_stdout, r1_stderr = audit._shellexec(cmd1)
        r2_stdout, r2_stderr = audit._shellexec(cmd2)

        if r1_stderr or r2_stderr:
            raise Exception(
                f"Error checking audit rules on {audit.hostname}: {r1_stderr or r2_stderr}"
            )

        if r1_stdout.splitlines() != expected_file_output:
            state += 1

        if r2_stdout.splitlines() != expected_auditctl_output:
            state += 2

        return state
    except FileNotFoundError:
        return "Audit rules directory not found."
    except Exception as e:
        return str(e)


def audit_bootloader_password_is_set(audit) -> int:
    try:
        state = 0
        cmd = R'grep "^\s*GRUB2_PASSWORD" /boot/grub2/user.cfg'
        r_stdout, r_stderr = audit._shellexec(cmd)

        if r_stderr:
            raise Exception(
                f"Error checking bootloader password on {audit.hostname}: {r_stderr}"
            )

        if not r_stdout.startswith("GRUB2_PASSWORD="):
            state += 1

        return state
    except FileNotFoundError:
        return "GRUB2 password configuration file not found."
    except Exception as e:
        return str(e)


def is_firewall_installed(audit) -> str:
    try:
        # Commands to check if common firewall packages are installed
        cmd_firewalld = "rpm -q firewalld"
        cmd_iptables = "rpm -q iptables"
        cmd_ufw = "dpkg -l | grep ufw"

        # Execute the commands
        r_firewalld, _ = audit._shellexec(cmd_firewalld)
        r_iptables, _ = audit._shellexec(cmd_iptables)
        r_ufw, _ = audit._shellexec(cmd_ufw)

        # Check results
        if "package firewalld is not installed" not in r_firewalld:
            return "Firewalld is installed."
        elif "package iptables is not installed" not in r_iptables:
            return "Iptables is installed."
        elif r_ufw:
            return "UFW is installed."
        else:
            return "No firewall package is installed."
    except Exception as e:
        return f"Error checking firewall packages: {str(e)}"
