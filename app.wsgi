import sys

print("python version = {}".format(sys.version_info))
activate_this = '/home/joe.suber/phones/bin/activate_this.py'
with open(activate_this) as file_:
    exec(file_.read(), dict(__file__=activate_this))
sys.path.insert(0, '/home/joe.suber/phones/')
from app import app as application
