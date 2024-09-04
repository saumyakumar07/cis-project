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
