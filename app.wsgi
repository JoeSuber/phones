import sys

# gets around the error caused by printing to stdout under mod_wsgi
sys.stdout = sys.stderr

# sets virtualenv python as the one to use:
activate_this = '/home/joe.suber/phones/bin/activate_this.py'
with open(activate_this) as file_:
    exec(file_.read(), dict(__file__=activate_this))

# puts the working dir on the path
sys.path.insert(0, '/home/joe.suber/phones/')

# import the app under the name mod_wsgi expects
from app import app as application
