from flask import Flask, render_template, request, make_response
from audit.ssh_config_audit import SSHConfigAudit
import json

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # try:
        # Retrieve the credentials JSON string from the form
        credentials_json = request.form.get("credentials", "[]")
        print("Received credentials JSON:", credentials_json)

        # Parse the JSON string into a Python list
        credentials = json.loads(credentials_json)
        print("Parsed Credentials:", credentials)

        all_results = []  # List to store results for each set of credentials

        for entry in credentials:
            hostname = entry.get("hostname")
            username = entry.get("username")
            password = entry.get("password")

            print(f"Processing Host: {hostname}, Username: {username}")

            # Initialize audit classes for each set of credentials
            ssh_audit = SSHConfigAudit(hostname, username, password)

            # Collect audit results for each host
            results = {
                "username": username,
                "hostname": hostname,
                "sshd_config": ssh_audit.is_root_login_disabled_message(),
                "ssh_no_auth": ssh_audit.is_password_authentication_disabled(),
                "ssh_protocol2": ssh_audit.is_ssh_protocol_set_to_2(),
                "empty_password_disabled": ssh_audit.is_empty_passwords_disabled(),
                "cramfs_disabled": ssh_audit.is_cramfs_disabled(),
                "is_squashfs_disabled": ssh_audit.is_squashfs_disabled(),
                "is_udf_disabled": ssh_audit.is_udf_disabled(),
                "tmp_partition": ssh_audit.is_tmp_partition(),
                "password_rotation_configured": ssh_audit.is_minimum_days_between_password_changes_configured(),
                "password_expiration": ssh_audit.is_password_expiration_365_days_or_less(),
                "file_access": ssh_audit.audit_events_for_unsuccessful_file_access_attempts_message(),
                "bootloader_password": ssh_audit.audit_bootloader_password_is_set_message(),
                "firewall": ssh_audit.is_firewall_installed_message(),
                "auditd": ssh_audit.is_package_installed("auditd"),
                "login_logout": ssh_audit.audit_events_for_login_and_logout_are_collected(),
                "password_delay": ssh_audit.audit_password_change_minimum_delay(),
                "default_root_gid_0": ssh_audit.is_default_group_for_root_gid_0(),
                "umask_027": ssh_audit.is_default_user_umask_027_or_more_restrictive(),
                # "user_shell_timeout_900": ssh_audit.is_default_user_shell_timeout_900_seconds_or_less(),
                "is_passwd_permission_configured": ssh_audit.are_permissions_on_etc_passwd_configured(),
                "is_passwd_dash_permission_configured": ssh_audit.are_permissions_on_etc_passwd_dash_configured(),
                "is_group_permission_configured": ssh_audit.are_permissions_on_etc_group_configured(),
                "etc_group_dash_configured": ssh_audit.are_permissions_on_etc_group_dash_configured(),
                "is_shadow_permission_configured": ssh_audit.are_permissions_on_etc_shadow_configured(),
                "is_shadow_dash_permission_configured": ssh_audit.are_permissions_on_etc_shadow_dash_configured(),
                "is_gshadow_permission_configured": ssh_audit.are_permissions_on_etc_gshadow_configured(),
                "is_gshadow_dash_permission_configured": ssh_audit.are_permissions_on_etc_gshadow_dash_configured(),
                # "no_world_writable_files": ssh_audit.are_no_world_writable_files(),
                # "etc_shadow_password_empty": ssh_audit.are_etc_shadow_password_fields_not_empty(),
                # "groups_in_passwd_exist": ssh_audit.do_all_groups_in_passwd_exist_in_group(),
                # "shadow_group_empty": ssh_audit.is_shadow_group_empty(),
                "no_duplicate_uids": ssh_audit.are_no_duplicate_uids(),
                "no_duplicate_gids": ssh_audit.are_no_duplicate_gids(),
                "no_duplicate_unames": ssh_audit.are_no_duplicate_user_names(),
                "no_duplicate_groups": ssh_audit.are_no_duplicate_group_names(),
                # "root_path_integrity": ssh_audit.is_root_path_integrity_ensured(),
                # "root_uid_0": ssh_audit.is_root_the_only_uid_0_account(),
                "local_interactive_user_home": ssh_audit.do_local_interactive_user_home_directories_exist(),
                # "local_interactive_own_home": ssh_audit.do_local_interactive_users_own_their_home_directories(),
                # "home_dir_750": ssh_audit.are_local_interactive_user_home_directories_mode_750_or_more_restrictive(),
            }

            all_results.append(results)

        # Pass the collected results for each host to the results template
        print("All Results:", all_results)

        # Render the template as HTML
        rendered_html = render_template("result.html", all_results=all_results)

        return rendered_html

    # except json.JSONDecodeError as e:
    #     print("JSON Decode Error:", e)
    #     return render_template("result.html", error="Invalid credentials format.")
    # except Exception as e:
    #     print("Unexpected Error:", e)
    #     return render_template("result.html", error="An unexpected error occurred.")

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
