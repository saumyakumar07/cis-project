import paramiko


def _connect(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname,
        username=username,
        password=password,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def _shellexec(client, cmd):
    stdin, stdout, stderr = client.exec_command(cmd)
    return stdout.read().decode("utf-8").strip(), stderr.read().decode("utf-8").strip()
