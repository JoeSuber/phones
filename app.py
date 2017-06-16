from flask import Flask, render_template, redirect, url_for, flash, session, request, get_flashed_messages
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from wtforms import StringField, PasswordField, BooleanField, IntegerField, ValidationError, SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# from flask_sslify import SSLify
import pickle, os, csv
from datetime import datetime, timedelta
import codecs

"""
# todo: take a look at codepen.io
# https://askubuntu.com/questions/865554/how-do-i-install-python-3-6-using-apt-get
# https://askubuntu.com/questions/716429/how-to-put-my-server-on-the-internet
# https://help.ubuntu.com/lts/serverguide/httpd.html#https-configuration
# ssl encrypt: https://www.youtube.com/watch?v=2iXfGn1Ur6U
# http://terokarvinen.com/2016/deploy-flask-python3-on-apache2-ubuntu

https://www.youtube.com/watch?v=cXL8FDUag-s

MEID to MEIDhex: http://www.howardforums.com/showthread.php/1433623-How-to-Calculate-MEID-DEC-and-P(ESN)
    https://github.com/arthurdejong/python-stdnum/blob/master/stdnum/meid.py

git config --list --show-origin

sudoedit /etc/apache2/sites-available/app.conf

## /etc/httpd/sites-available/app.conf
<VirtualHost *:80>
 ServerName www.dvtandc.com/inventory

 WSGIDaemonProcess app user=joe.suber group=joe.suber threads=5 home=/user/joe.suber/phones
 WSGIScriptAlias /inventory /home/joe.suber/phones/app.wsgi

<Directory /home/joe.suber/phones/>
 WSGIProcessGroup app
 WSGIApplicationGroup %{GLOBAL}
 WSGIScriptReloading On

 Require all granted
</Directory>
</VirtualHost>

"""
###################################################################################
# DONT FORGET! to uncomment the '@login_required' for newperson() upon deployment
###################################################################################

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
#sslify = SSLify(app, subdomains=True)

__dbfn__ = "DVTCinventory"
__sqlext__ = '.sqlite'
__sql_inventory_fn__ = os.path.join(os.getcwd(), (__dbfn__ + __sqlext__))
print("Database file located at: {}".format(__sql_inventory_fn__))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + __sql_inventory_fn__
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WERKZEUG_DEBUG_PIN'] = False
app.config.update(
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 465,
    MAIL_USE_SSL = True,
    MAIL_USERNAME = 'joe.suber@dvtandc.com',
    MAIL_PASSWORD = ''
)

Bootstrap(app)
mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


###########################
#### Database Tables ######
###########################
class User(UserMixin, db.Model):
    __tablename__ = "people"
    id = db.Column(db.Integer, primary_key=True)
    badge = db.Column(db.String(40), unique=True)
    username = db.Column(db.String(40), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(94))
    phone_number = db.Column(db.String(12))
    admin = db.Column(db.Boolean)


class Phone(db.Model):
    """  will add relations to User ...http://flask-sqlalchemy.pocoo.org/2.1/quickstart/"""
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    MEID = db.Column(db.String(28), unique=True)
    SKU = db.Column(db.String(50))
    MODEL = db.Column(db.String(50))
    OEM = db.Column(db.String(16))
    Serial_Number = db.Column(db.String(50))
    Hardware_Version = db.Column(db.String(50))
    In_Date = db.Column(db.DateTime)
    Archived = db.Column(db.Boolean)
    TesterId = db.Column(db.Integer)
    DVT_Admin = db.Column(db.String(80))
    MSL = db.Column(db.String(50))
    History = db.Column(db.LargeBinary)
    Comment = db.Column(db.String(255))

db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##########################
##### Validators #########
##########################
class Unique(object):
    """ validator for FlaskForm that demands field uniqueness against the current database entries """
    def __init__(self, model, field, message=None):
        self.model = model
        self.field = field
        if not message:
            message = u'not validated'
        self.message = message

    def __call__(self, form, field):
        check = self.model.query.filter(self.field == field.data).first()
        if check:
            raise ValidationError(self.message)


class Exists(Unique):
    """ validator for FlaskForm that demands that an item exists """
    def __call__(self, form, field):
        check = self.model.query.filter(self.field == field.data).first()
        if not check:
            raise ValidationError(self.message)


##########################
######## Forms ###########
##########################
class BadgeEntryForm(FlaskForm):
    badge = StringField('badge', validators=[InputRequired(),
                                             Length(min=4, max=40),
                                             Exists(User, User.badge,
                                                    message="Badge does not belong to a registered user")])


class MeidForm(FlaskForm):
    meid = StringField('MEID', validators=[InputRequired(),
                                           Exists(Phone, Phone.MEID,
                                                  message="MEID does not match any devices in database")])


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(),
                                                   Exists(User, User.username, message="Not a registered username")])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(min=4, max=50),
                                             Unique(User, User.email, message="Email address already in use")])
    badge = StringField('badge', validators=[InputRequired(), Length(min=10, max=80),
                                             Unique(User, User.badge, message="Badge number already assigned!")])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15),
                                                   Unique(User, User.username, message="Please choose another name")])
    password = PasswordField('password', validators=[InputRequired(),
                                                     Length(min=8, max=80, message="Passwords are 8-80 characters")])
    phone_number = StringField('phone xxx-xxx-xxxx', validators=[InputRequired(), Length(min=4, max=12)])
    admin = BooleanField('admin ')


class NewDevice(FlaskForm):
    OEM = StringField('OEM', validators=[InputRequired()])
    MEID = StringField('MEID', validators=[InputRequired(), Length(min=10, max=24),
                                           Unique(Phone, Phone.MEID, message="This MEID is already in the database")])
    SKU = StringField('SKU', validators=[InputRequired(), Length(min=2, max=80)])
    MODEL = StringField('MODEL', validators=[InputRequired(), Length(min=2, max=80)])
    Hardware_Version = StringField('Hardware Version', validators=[InputRequired(), Length(min=1, max=40)])
    Serial_Number = StringField('Serial Number', validators=[InputRequired(), Length(min=6, max=16)])
    Archived = BooleanField('Archived ')
    MSL = StringField('MSL', validators=[InputRequired()])
    Comment = StringField('Comment')


class ChangePassword(FlaskForm):
    account = StringField('user name for which we will change the password: ', validators=[InputRequired(),
                                                   Exists(User, User.username, message="Not a registered username")])
    password = PasswordField('new password:', validators=[InputRequired(), Length(min=8, max=80)])
    retype = PasswordField('re-type   :', validators=[InputRequired(), Length(min=8, max=80)])


class OemForm(FlaskForm):
    OEM = StringField('OEM name', validators=[InputRequired(), Exists(Phone, Phone.OEM, message="No OEM by that name!")])


class OverdueForm(FlaskForm):
    timeframe = IntegerField('Number of Days', validators=[InputRequired()])


###########################
####### Routes ############
###########################
sub = ''

@app.route('/', methods=['GET', 'POST'])
def index():
    # step 1, get the badge to get the user
    session['userid'] = None
    form = BadgeEntryForm()
    if form.validate_on_submit():
        user = User.query.filter_by(badge=form.badge.data).first()
        session['userid'] = user.id
        return redirect(url_for('meid'))
    message = None
    if 'message' in session:
        message = session.pop('message')

    return render_template('index.html', form=form, message=message)


@app.route(sub + '/meid', methods=['GET', 'POST'])
def meid():
    # step 2, get the device, change owner
    form = MeidForm()
    if form.validate_on_submit():
        device = Phone.query.filter_by(MEID=form.meid.data).first()
        if device and session['userid']:
            # change owner of device and append new owner to history blob ####
            device.TesterId = session['userid']
            device.In_Date = datetime.utcnow()
            history = pickle.loads(device.History)
            history.append((session['userid'], datetime.utcnow()))
            device.History = pickle.dumps(history)
            db.session.commit()
            session['message'] = "{} takes: {} - {}  {}  meid: {}".format(load_user(session['userid']).username,
                                                                          device.OEM, device.SKU, device.MODEL,
                                                                          device.MEID)
            session['userid'], device = None, None
        return redirect(url_for('index'))   # success!

    if ('userid' in session) and session['userid']:
        username = load_user(session['userid']).username
    else:
        session['message'] = "Enter destination badge first:"
        return redirect(url_for('index'))   #  fail! probably tried to access page directly

    return render_template('meid.html', form=form, name=username)


@app.route(sub + '/newperson', methods=['GET', 'POST'])
# @login_required  ### <-- uncomment after adding first admin user to database
def newperson():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        logged = User(badge=form.badge.data,
                      email=form.email.data,
                      username=form.username.data,
                      password=hashed_password,
                      phone_number=form.phone_number.data,
                      admin=form.admin.data)
        db.session.add(logged)
        db.session.commit()
        print("NEW USER!  {}".format(logged.username))
        flash("created new user: {}".format(logged.username))
        return redirect(url_for('admin'))

    return render_template('signup.html', form=form)


@app.route(sub + '/newdevice', methods=['GET', 'POST'])
@login_required
def newdevice():
    form = NewDevice()
    if form.validate_on_submit():
        new_device = Phone(OEM=form.OEM.data,
                           MEID=form.MEID.data,
                           SKU=form.SKU.data,
                           MODEL=form.MODEL.data,
                           Serial_Number=form.Serial_Number.data,
                           Hardware_Version=form.Hardware_Version.data,
                           MSL=form.MSL.data,
                           History=pickle.dumps([(session['userid'], datetime.utcnow())]),
                           Comment=form.Comment.data,
                           Archived=form.Archived.data,
                           In_Date=datetime.utcnow(),
                           DVT_Admin=current_user.id)
        db.session.add(new_device)
        db.session.commit()
        return redirect(url_for('newdevice'))
    return render_template('newdevice.html', form=form)


@app.route(sub + '/admin')
@login_required
def admin():
    user = User.query.get(int(current_user.id))
    if user.admin:
        return render_template('admin.html', name=user.username)
    return redirect(url_for('login'))


@app.route(sub + '/newpass', methods=['GET', 'POST'])
@login_required
def newpass():
    message = None
    user = User.query.get(int(current_user.id))
    form = ChangePassword()
    if form.validate_on_submit() and user.admin:
        changer = User.query.filter_by(username=form.account.data).first()
        # allow any admin to change any non-admin. Only allow admin to change their own.
        print("user.username = {}".format(user.username))
        print("changer.username = {}".format(changer.username))
        if (not changer.admin) or (user.username == changer.username):
            if form.password.data == form.retype.data:
                changer.password = generate_password_hash(form.password.data)
                db.session.commit()
                print("Changed password for: {}".format(changer.username))
                return redirect(url_for('admin'))
            message = "Password fields don't match!"
        else:
            message = "NOT ALLOWED to change another admin's password"
    return render_template('newpass.html', form=form, name=user.username, message=message)


@app.route(sub + '/meidedit', methods=['GET', 'POST'])
@login_required
def meidedit():
    form = MeidForm()
    user = User.query.get(int(current_user.id))
    print("user.admin = {}".format(user.admin))
    if form.validate_on_submit() and user.admin:
        print("checking MEID {}".format(form.meid.data))
        session['editingMEID'] = form.meid.data
        return redirect(url_for('editdevice'))
    return render_template('meidedit.html', form=form)


@app.route(sub + '/editdevice', methods=['GET', 'POST'])
@login_required
def editdevice():
    try:
        device = Phone.query.filter_by(MEID=session['editingMEID']).first()
    except KeyError:    # protect against false access attempt
        return redirect(url_for('meidedit'))
    # fill is some form blanks for user:
    newform = NewDevice(MEID=device.MEID,
                        SKU=device.SKU,
                        OEM=device.OEM,
                        MODEL=device.MODEL,
                        Serial_Number=device.Serial_Number,
                        Hardware_Version=device.Hardware_Version,
                        MSL=device.MSL,
                        Archived=device.Archived,
                        Comment=device.Comment)
    if request.method == "POST":
        history = pickle.loads(device.History)
        history.append((current_user.id, datetime.utcnow()))
        device.SKU = newform.SKU.data
        device.OEM = newform.OEM.data
        device.MODEL = newform.MODEL.data
        device.Serial_Number = newform.Serial_Number.data
        device.Hardware_Version = newform.Hardware_Version.data
        device.MSL = newform.MSL.data
        device.Archived = newform.Archived.data
        device.Comment = newform.Comment.data
        device.History = pickle.dumps(history)
        db.session.commit()
        used = session.pop('editingMEID')
        print(" {} MEID = {} was updated".format(device.SKU, used))
        return render_template('admin.html')
    return render_template('editdevice.html', form=newform)


@app.route(sub + '/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    message = None
    if request.method == 'GET':
        session['sent_from'] = request.args.get('next')
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            session['userid'] = user.id
            sent_from = session['sent_from']
            session['sent_from'] = None
            return redirect(sent_from or url_for('index'))
        message = "Incorrect Password"
    return render_template('login.html', form=form, message=message)


@app.route(sub + '/oemreport', methods=['GET', 'POST'])
@login_required
def oemreport():
    user = load_user(current_user.id)
    form = OemForm()
    if form.validate_on_submit():
        email, fn = oem_report(current_user.id,
                               form.OEM.data,
                               os.path.join(os.getcwd(), '{}_{}.csv'.format(user.username, form.OEM.data)))
        send_report(email, fn, subject='OEM-{} report'.format(form.OEM.data))
        return render_template('oemreport.html', form=form, message='report on {} sent!'.format(form.OEM.data))
    return render_template('oemreport.html', form=form, message="send report to: " + user.email)


@app.route(sub + '/overdue', methods=['GET', 'POST'])
@login_required
def overdue():
    user=load_user(current_user.id)
    form=OverdueForm()
    if form.validate_on_submit():
        email, fn = overdue_report(current_user.id,
                                   days=form.timeframe.data,
                                   outfile=os.path.join(os.getcwd(), '{}_overdue.csv'.format(user.username)))
        send_report(email, fn, subject="Overdue devices report")
        return render_template('overdue.html', form=form, message="overdue devices report sent")
    return render_template('overdue.html', form=form,
                           message="Please enter the number of days 'out' you are interested in")


@app.route(sub + '/logout')
@login_required
def logout():
    logout_user()
    session['userid'] = None
    return redirect(url_for('index'))

################################
###### Import/Export Data ######
################################

""" _columns must be the same at time of import and export to assure the proper labels """

_columns = ['MEID', 'OEM', 'MODEL', 'SKU', 'Serial_Number', 'Hardware_Version',
           'In_Date', 'Archived', 'TesterId', 'DVT_Admin', 'MSL', 'Comment']


def csv_template(outfile=None):
    """ create a spreadsheet template for project managers to fill using the _column list """
    if not outfile:
        outfile = os.path.join(os.getcwd(), "your_own_devices.csv")
    with open(outfile, 'w', newline='') as output:
        spamwriter = csv.writer(output, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        spamwriter.writerow(_columns)
    print("spreadsheet columns exported to: {}".format(outfile))


def csv_dump(phones_fn=None):
    """ Call from console to get a dump file that can be re-imported
        or examined as a csv.
        WARNING: does not preserve passwords or device history """
    from collections import Counter
    if not phones_fn:
        phones_fn = os.path.join(os.getcwd(), "all_devices.csv")
    existing_items = Phone.query.all()
    if report_spamer(existing_items, phones_fn):
        print("dumped {} lines of device data".format(len(existing_items)))
    existing_people = User.query.all()
    people_columns = []
    for k in User.__dict__.keys():
        dunders = Counter(k)
        if dunders['_'] > 1:
            continue
        people_columns.append(k)
    for peep in existing_people:
        print("****")
        for stat in people_columns:
            print("{}: {}".format(stat, peep.__dict__[stat]))


def datefix(datestr):
    """ transform string into a python datetime object 
        handle mm/dd/yy or mm/dd/yyyy or dashes instead of slashes """
    fix = datestr.replace('-','/')
    if len(fix) > 4:
        try:
            return datetime.strptime(fix, "%m/%d/%y")
        except ValueError:
            return datetime.strptime(fix, "%m/%d/%Y")
    return datetime.utcnow()


def csv_import(filename=None):
    """ Assumes users have kept columns in the _column list-order.
        Puts csv spreadsheet-derived data into database.
        (to use, download and save the inventory sheets as .csv files with those
        particular columns)
        """
    if not filename:
        filename = os.path.join(os.getcwd(), "scotts.csv")
    columns = _columns
    new_item_count, existing_item_count = 0, 0
    with open(filename, "rU") as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',', quotechar='"')
        column_checksum = len(columns)
        for num, line in enumerate(spamreader):
            if not new_item_count:  # skip the row labels
                new_item_count = 1
                continue
            row = {label: item.strip() for label, item in zip(columns, line)}
            if len(row) != column_checksum:
                print("ABORT! on bad row: {}".format(row))
                print("Import not finished! Fix data")
                exit(1)
            # check that item is not already in database
            existing_item = Phone.query.filter_by(MEID=row['MEID']).first()
            if existing_item:
                existing_item_count += 1
                print("!{:5} Item exists {}".format(num, row['MEID']))
                continue

            print("#{:5}: {}".format(num, row))
            new_device = Phone(OEM=row['OEM'],
                               MEID=row['MEID'],
                               SKU=row['SKU'],
                               MODEL=row['MODEL'],
                               Serial_Number=row['Serial_Number'],
                               Hardware_Version=row['Hardware_Version'],
                               MSL=row['MSL'].strip('"'),
                               History=pickle.dumps([(row['DVT_Admin'], datetime.utcnow())]),
                               Comment=row['Comment'].replace(os.linesep, ' '),
                               In_Date=datefix(row['In_Date']),
                               Archived=bool(row['Archived']),
                               TesterId=row['TesterId'],
                               DVT_Admin=row['DVT_Admin'])
            try:
                db.session.add(new_device)
                new_item_count += 1
            except Exception as e:
                print("ER: {}, {}".format(e, new_device))

        db.session.commit()
    print("imported {} items".format(new_item_count - 1))
    print("ignored {} existing items".format(existing_item_count))
    return True


def import_all_sheets(fns=None):
    """ gather up the .csv files and import them all at once """
    base = os.getcwd()
    if not fns:
        fns = [os.path.join(base, fn) for fn in os.listdir(base) if fn.endswith(".csv")]
    for fn in fns:
        print("processing {}".format(fn))
        csv_import(filename=fn)
    return 1


def nameid(id_num):
    """ try to find a human readable string to go with the id number """
    person = None
    if id_num:
        person = User.query.get(int(id_num))
    if person:
        return person.username
    return ''


def report_spamer(spam_list, outfn):
    """ writes out reports to a csv that can be opened into a spreadsheet"""
    columns = _columns
    with open(outfn, 'w', newline='') as output_obj:
        spamwriter = csv.writer(output_obj, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        spamwriter.writerow(columns) # column labels
        for i in spam_list:
            line = [i.MEID, i.OEM, i.MODEL, i.SKU, i.Serial_Number, i.Hardware_Version, str(i.In_Date.date()),
                    i.Archived, nameid(i.TesterId), nameid(i.DVT_Admin), i.MSL, i.Comment]
            spamwriter.writerow(line)
    print("report file written to = {}".format(outfn))
    return True


def overdue_report(manager_id, days=14, outfile=None):
    """ query by manager to find devices that need checking-up on
        write a report that can be sent as an attachment to managers. return filename. """
    if outfile is None:
        outfile = os.path.join(os.getcwd(), "overdue_report.csv")
    manager = User.query.get(manager_id)
    try:
        assert manager.admin
    except AssertionError:
        responce = "User: {} is not an Administrator".format(manager.username)
        print(responce)
        return None, responce
    today = datetime.utcnow()
    delta = timedelta(days)
    overdue_stuff = [phone for phone in Phone.query.filter_by(DVT_Admin=manager.id).all()
                     if ((today - phone.In_Date) > delta) and phone.TesterId]

    report_spamer(overdue_stuff, outfile)
    return manager.email, outfile


def oem_report(manager_id, oem=None, outfile=None):
    """ prepare a .csv report that lists all devices from a particular OEM 
        or just return all devices from a manager (old and gone: filter by manager and OEM)"""
    manager = User.query.get(manager_id)
    if outfile is None:
        outfile = os.path.join(os.getcwd(), "oem_report.csv")
    if oem is None:
        results = Phone.query.filter_by(DVT_Admin=manager_id).all()
    else:
        results = Phone.query.filter_by(OEM=oem).all()

    report_spamer(results, outfile)
    return manager.email, outfile


def send_report(email, attachment_fn, sender=None, subject='Overdue Devices Report'):
    """ email an attachment """
    if sender is None:
        sender=app.config['MAIL_USERNAME']
    human_name = os.path.split(attachment_fn)[-1]
    message = Message(subject=subject + " " + human_name,
                      sender=sender,
                      recipients=[email])
    with app.open_resource(attachment_fn) as attachment:
        message.attach(human_name, "spreadsheet/csv", attachment.read())
    mail.send(message)
    print("sent mail from {} to {}".format(sender, email))
    return True


def dumpty():
    with codecs.open("C:\\Users\\2053_HSUF\\Desktop\\adblogcat.txt", 'rU', 'utf-16') as fob:
        for linenum, line in enumerate(fob.readlines()):
            parts = line.strip().split(":")
            try:
                print(linenum, " : ", parts[2].split(' ')[-1])
            except:
                print("badline_____________________")


if __name__ == '__main__':
    #app.run(debug=True)
    app.run(host='0.0.0.0', port=5000, debug=False)
