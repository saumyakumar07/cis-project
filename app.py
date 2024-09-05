from flask import Flask, render_template, request
from audit.ssh_config_audit import SSHConfigAudit

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    results = {}
    if request.method == "POST":
        hostname = request.form["hostname"]
        username = request.form["username"]
        password = request.form["password"]

        # Initialize audit classes
        ssh_audit = SSHConfigAudit(hostname, username, password)

        # Perform audits and collect results
        results["sshd_config"] = ssh_audit.is_root_login_disabled_message()
        results["ssh_no_auth"] = ssh_audit.is_password_authentication_disabled()
        results["ssh_protocol2"] = ssh_audit.is_ssh_protocol_set_to_2()
        results["empty_password_disabled"] = ssh_audit.is_empty_passwords_disabled()
        results["cramfs_disabled"] = ssh_audit.is_cramfs_disabled()
        results["is_squashfs_disabled"] = ssh_audit.is_squashfs_disabled()
        results["is_udf_disabled"] = ssh_audit.is_udf_disabled()
        results["tmp_partition"] = ssh_audit.is_tmp_partition()
        results["password_rotation_configured"] = (
            ssh_audit.is_minimum_days_between_password_changes_configured()
        )
        results["password_expiration"] = (
            ssh_audit.is_password_expiration_365_days_or_less()
        )
        results["users_last_password_change_date"] = (
            ssh_audit.are_all_users_last_password_change_dates_in_past()
        )
        results["system_accounts_secured"] = ssh_audit.are_system_accounts_secured()

        results["file_access"] = (
            ssh_audit.audit_events_for_unsuccessful_file_access_attempts_message()
        )
        results["bootloader_password"] = (
            ssh_audit.audit_bootloader_password_is_set_message()
        )
        results["firewall"] = ssh_audit.is_firewall_installed_message()
        results["auditd"] = ssh_audit.is_package_installed("auditd")
        results["login_logout"] = (
            ssh_audit.audit_events_for_login_and_logout_are_collected()
        )
        results["password_delay"] = ssh_audit.audit_password_change_minimum_delay()

        return render_template("result.html", results=results)
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
