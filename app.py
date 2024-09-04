from flask import Flask, render_template, request
import paramiko

app = Flask(__name__)

class SSHConfigAudit:
    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.client = self._connect()

    def _connect(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.hostname, username=self.username, password=self.password, allow_agent=False, look_for_keys=False)
        return client

    def _shellexec(self, cmd):
        stdin, stdout, stderr = self.client.exec_command(cmd)
        return stdout.read().decode('utf-8'), stderr.read().decode('utf-8')

    def is_root_login_disabled(self) -> bool:
        cmd = "grep -i '^PermitRootLogin' /etc/ssh/sshd_config"
        stdout, stderr = self._shellexec(cmd)

        if stderr:
            raise Exception(f"Error checking sshd_config on {self.hostname}: {stderr}")

        if 'PermitRootLogin no' in stdout:
            return True
        elif 'PermitRootLogin' in stdout:
            return False
        else:
            return False

    def close(self):
        self.client.close()


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        hostname = request.form['hostname']
        username = request.form['username']
        password = request.form['password']
        
        try:
            audit = SSHConfigAudit(hostname, username, password)
            is_disabled = audit.is_root_login_disabled()
            audit.close()
            result = "Root login is disabled." if is_disabled else "Root login is enabled or not explicitly disabled."
        except Exception as e:
            result = f"Error: {str(e)}"
        
        return render_template('result.html', result=result)

    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)

