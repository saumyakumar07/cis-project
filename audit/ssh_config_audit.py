from .utils import _connect, _shellexec
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

    def is_root_login_disabled_message(self):
        result = is_root_login_disabled(self)
        return (
            result
            if isinstance(result, str)
            else (
                "Root login is disabled."
                if result
                else "Root login is enabled or not explicitly disabled."
            )
        )

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

    def close(self):
        self.client.close()


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
