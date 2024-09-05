from .utils import _connect, _shellexec
import os
from .audit_functions import (
    is_root_login_disabled,
    audit_events_for_unsuccessful_file_access_attempts,
    audit_bootloader_password_is_set,
    is_firewall_installed,
)


class SSHConfigAudit:
    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.client = self._connect()

    def _connect(self):
        return _connect(self.hostname, self.username, self.password)

    def _shellexec(self, cmd):
        return _shellexec(self.client, cmd)

    def is_root_login_disabled_message(self) -> dict:
        cmd = "grep -i 'PermitRootLogin' /etc/ssh/sshd_config"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(f"Error checking sshd_config on {self.hostname}: {stderr}")

        if "PermitRootLogin no" in stdout:
            return {"message": "Root login is disabled.", "color": "green"}
        else:
            return {"message": "Root login is enabled.", "color": "red"}

    def audit_events_for_unsuccessful_file_access_attempts_message(self):
        result = audit_events_for_unsuccessful_file_access_attempts(self)
        if isinstance(result, str):
            return result
        elif result == 0:
            return "Unsuccessful file access attempts are being properly logged."
        else:
            return f"Unsuccessful file access attempts are not being properly logged (state {result})."

    def audit_bootloader_password_is_set_message(self):
        result = audit_bootloader_password_is_set(self)
        if isinstance(result, str):
            return result
        elif result == 0:
            return "Bootloader password is set."
        else:
            return "Bootloader password is not set."

    def is_firewall_installed_message(self):
        return is_firewall_installed(self)

    def is_package_installed(self, package_name: str) -> str:
        cmd = f"dpkg -l | grep {package_name}"
        stdout, stderr = self._shellexec(cmd)

        if stderr:
            return f"Error checking package installation: {stderr[0]}"

        if stdout:
            return f"The package '{package_name}' is installed."
        else:
            return f"The package '{package_name}' is not installed."

    def audit_events_for_login_and_logout_are_collected(self) -> int:
        state = 0
        cmd1 = "grep -h logins /etc/audit/rules.d/*.rules"
        cmd2 = "auditctl -l | grep logins"

        expected_output = [
            "-w /var/log/lastlog -p wa -k logins",
            "-w /var/run/faillock -p wa -k logins",
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1[0] != expected_output:
            state += 1

        if r2[0] != expected_output:
            state += 2
        check_name = "Audit events for login and logout are collected"
        return interpret_result(state, check_name)

    def audit_password_change_minimum_delay(self, expected_min_days: int = 1) -> int:
        state = 0

        cmd1 = R"grep ^\s*PASS_MIN_DAYS /etc/login.defs"
        cmd2 = R"grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,4"

        r1_stdout, r1_stderr = self._shellexec(cmd1)
        r2_stdout, r2_stderr = self._shellexec(cmd2)

        # Check if PASS_MIN_DAYS is less than expected_min_days
        if not r1_stdout or int(r1_stdout[0].split()[1]) < expected_min_days:
            state += 1

        # Check /etc/shadow entries for minimum days between password changes
        for line in r2_stdout:
            if line.strip() != "":
                days = line.split(":")[1]
                if not days.isdigit() or int(days) < expected_min_days:
                    state += 2
                    break

        return interpret_result(state, "Password change minimum delay")

    def is_password_authentication_disabled(self) -> bool:
        cmd = "grep -i 'PasswordAuthentication' /etc/ssh/sshd_config"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(f"Error checking sshd_config on {self.hostname}: {stderr}")
        if "PasswordAuthentication no" in stdout:
            return "PasswordAuthentication is disabled."

        else:
            return "PasswordAuthentication is enabled."

    def is_ssh_protocol_set_to_2(self) -> bool:
        cmd = "grep -i 'Protocol' /etc/ssh/sshd_config"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(f"Error checking sshd_config on {self.hostname}: {stderr}")

        if "Protocol 2" in stdout:
            return "Protocol 2 is set."
        else:
            return "Protocol 2 is not set."

    def is_empty_passwords_disabled(self) -> bool:
        cmd = "grep -i 'PermitEmptyPasswords' /etc/ssh/sshd_config"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(f"Error checking sshd_config on {self.hostname}: {stderr}")

        if "PermitEmptyPasswords no" in stdout:
            return "Empty passwords are disabled."
        else:
            return "Empty passwords are enabled."

    def is_cramfs_disabled(self) -> bool:
        cmd = "grep -i 'cramfs' /etc/fstab"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(f"Error checking /etc/fstab on {self.hostname}: {stderr}")
        if not stdout:
            return "cramfs is not in /etc/fstab"
        else:
            return "cramfs is in /etc/fstab"

    def is_squashfs_disabled(self) -> bool:
        cmd = "grep -i 'squashfs' /etc/fstab"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(f"Error checking /etc/fstab on {self.hostname}: {stderr}")
        if not stdout:
            return "squashfs is not in /etc/fstab"
        else:
            return "squashfs is in /etc/fstab"

    def is_udf_disabled(self) -> bool:
        cmd = "grep -i 'udf' /etc/fstab"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(f"Error checking /etc/fstab on {self.hostname}: {stderr}")
        if not stdout:
            return "udf is not in /etc/fstab"
        else:
            return "udf is in /etc/fstab"

    def is_tmp_partition(self) -> bool:
        cmd = "df -h | grep '/tmp'"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking /tmp partition on {self.hostname}: {stderr}"
            )
        if not stdout:
            return "No /tmp partition found"
        else:
            return "/tmp partition found"

    def is_minimum_days_between_password_changes_configured(self) -> bool:
        cmd = "grep '^PASS_MIN_DAYS' /etc/login.defs"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking minimum days between password changes on {self.hostname}: {stderr}"
            )
        if not stdout:
            return "PASS_MIN_DAYS not found in /etc/login.defs. So password change minimum delay is not configured."
        else:
            return "PASS_MIN_DAYS found in /etc/login.defs. So password change minimum delay is configured."

    def is_password_expiration_365_days_or_less(self) -> bool:
        cmd = "grep '^PASS_MAX_DAYS' /etc/login.defs"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking password expiration on {self.hostname}: {stderr}"
            )
        try:
            days = int(stdout.strip().split()[1])
        except ValueError:
            return False

        if days <= 365:
            return "Password expiration is 365 days or less."
        else:
            return "Password expiration is more than 365 days."

    def are_all_users_last_password_change_dates_in_past(self) -> bool:
        cmd = "chage -l $(awk -F: '($3>=1000){print $1}' /etc/passwd | xargs)"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking users' last password change dates on {self.hostname}: {stderr}"
            )
        if "never" not in stdout.lower():
            return "No users last password change dates found."
        else:
            return "All users' last password change dates are in the past."

    def are_system_accounts_secured(self) -> bool:
        cmd = "awk -F: '($3<1000){print $1}' /etc/passwd | xargs -n1 chage -l"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking system accounts security on {self.hostname}: {stderr}"
            )
        return "password must be changed" not in stdout.lower()

    def close(self):
        if self.client:
            self.client.close()

    def is_default_group_for_root_gid_0(self) -> bool:
        cmd = "grep '^root' /etc/passwd"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking root's default group on {self.hostname}: {stderr}"
            )
        if "0" in stdout.split(":")[3]:
            return "Root's default group is gid 0."
        else:
            return "Root's default group is not gid 0."

    def is_default_user_umask_027_or_more_restrictive(self) -> bool:
        cmd = "grep 'umask' /etc/profile"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking default user umask on {self.hostname}: {stderr}"
            )
        if "027" in stdout:
            return "Default user umask is 027 or more restrictive."
        else:
            return "Default user umask is less restrictive than 027."

    def are_permissions_on_etc_passwd_configured(self) -> bool:
        cmd = "stat /etc/passwd"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking permissions on /etc/passwd on {self.hostname}: {stderr}"
            )
        if "600" in stdout or "644" in stdout:
            return "Permissions on /etc/passwd are configured."
        else:
            return "Permissions on /etc/passwd are not configured."

    def are_permissions_on_etc_passwd_dash_configured(self) -> bool:
        cmd = "stat /etc/passwd-"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking permissions on /etc/passwd- on {self.hostname}: {stderr}"
            )
        if "600" in stdout or "644" in stdout:
            return "Permissions on /etc/passwd- are configured."
        else:
            return "Permissions on /etc/passwd- are not configured."

    def are_permissions_on_etc_group_configured(self) -> bool:
        cmd = "stat /etc/group"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking permissions on /etc/group on {self.hostname}: {stderr}"
            )
        if "600" in stdout or "644" in stdout:
            return "Permissions on /etc/group are configured."
        else:
            return "Permissions on /etc/group are not configured."

    def are_permissions_on_etc_group_dash_configured(self) -> bool:
        cmd = "stat /etc/group-"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking permissions on /etc/group- on {self.hostname}: {stderr}"
            )
        if "600" in stdout or "644" in stdout:
            return "Permissions on /etc/group- are configured."
        else:
            return "Permissions on /etc/group- are not configured."

    def are_permissions_on_etc_shadow_configured(self) -> bool:
        cmd = "stat /etc/shadow"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking permissions on /etc/shadow on {self.hostname}: {stderr}"
            )
        if "000" in stdout or "600" in stdout:
            return "Permissions on /etc/shadow are configured."
        else:
            return "Permissions on /etc/shadow are not configured."

    def are_permissions_on_etc_shadow_dash_configured(self) -> bool:
        cmd = "stat /etc/shadow-"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking permissions on /etc/shadow- on {self.hostname}: {stderr}"
            )
        if "000" in stdout or "600" in stdout:
            return "Permissions on /etc/shadow- are configured."
        else:
            return "Permissions on /etc/shadow- are not configured."

    def are_permissions_on_etc_gshadow_configured(self) -> bool:
        cmd = "stat /etc/gshadow"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking permissions on /etc/gshadow on {self.hostname}: {stderr}"
            )
        if "000" in stdout or "600" in stdout:
            return "Permissions on /etc/gshadow are configured."
        else:
            return "Permissions on /etc/gshadow are not configured"

    def are_permissions_on_etc_gshadow_dash_configured(self) -> bool:
        cmd = "stat /etc/gshadow-"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking permissions on /etc/gshadow- on {self.hostname}: {stderr}"
            )
        if "000" in stdout or "600" in stdout:
            return "Permissions on /etc/gshadow- are configured."
        else:
            return "Permissions on /etc/gshadow- are not configured."

    def are_no_unowned_files_or_directories(self) -> bool:
        cmd = "find / -nouser"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking unowned files on {self.hostname}: {stderr}"
            )
        if len(stdout.strip()) == 0:
            return "No unowned files found"
        else:
            return "Unowned files found"

    def are_no_ungrouped_files_or_directories(self) -> bool:
        cmd = "find / -nogroup"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking ungrouped files on {self.hostname}: {stderr}"
            )
        if len(stdout.strip()) == 0:
            return "No ungrouped files found"
        else:
            return "Ungrouped files found"

    def do_accounts_in_passwd_use_shadowed_passwords(self) -> bool:
        passwd_entries = self._read_file("/etc/passwd")
        shadow_entries = self._read_file("/etc/shadow")
        passwd_users = {entry.split(":")[0] for entry in passwd_entries}
        shadow_users = {entry.split(":")[0] for entry in shadow_entries}

        if passwd_users.issubset(shadow_users):
            return "Accounts in /etc/passwd use shadowed passwords"
        else:
            return "Accounts in /etc/passwd do not use shadowed passwords"

    def are_no_duplicate_uids(self) -> bool:
        cmd = "cut -d: -f3 /etc/passwd | sort | uniq -d"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking duplicate UIDs on {self.hostname}: {stderr}"
            )
        if len(stdout.strip()) == 0:
            return "No duplicate UIDs found"
        else:
            return "Duplicate UIDs found"

    def are_no_duplicate_gids(self) -> bool:
        cmd = "cut -d: -f3 /etc/group | sort | uniq -d"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking duplicate GIDs on {self.hostname}: {stderr}"
            )
        if len(stdout.strip()) == 0:
            return "No duplicate GIDs found"
        else:
            return "Duplicate GIDs found"

    def are_no_duplicate_user_names(self) -> bool:
        cmd = "cut -d: -f1 /etc/passwd | sort | uniq -d"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking duplicate user names on {self.hostname}: {stderr}"
            )
        if len(stdout.strip()) == 0:
            return "No duplicate user names found"
        else:
            return "Duplicate user names found"

    def are_no_duplicate_group_names(self) -> bool:
        cmd = "cut -d: -f1 /etc/group | sort | uniq -d"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking duplicate group names on {self.hostname}: {stderr}"
            )
        if len(stdout.strip()) == 0:
            return "No duplicate group names found"
        else:
            return "Duplicate group names found"

    def do_local_interactive_user_home_directories_exist(self) -> bool:
        cmd = "awk -F: '($3>=1000 && $3<65534){print $6}' /etc/passwd"
        stdout, stderr = self._shellexec(cmd)
        if stderr:
            raise Exception(
                f"Error checking local interactive user home directories on {self.hostname}: {stderr}"
            )
        home_dirs = stdout.strip().split("\n")
        return all(os.path.isdir(d) for d in home_dirs)


def interpret_result(result_code: int, check_name: str) -> str:
    if result_code == 0:
        return f"{check_name}: Passed"
    elif result_code == 1:
        return f"{check_name}: Failed - Issues found"
    elif result_code == 2:
        return f"{check_name}: Failed - Additional issues found"
    elif result_code == 3:
        return f"{check_name}: Multiple issues found"
    else:
        return f"{check_name}: Unknown result code {result_code}"
