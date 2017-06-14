import sys

print("python version = {}".format(sys.version_info))

sys.path.insert(0, '/home/joe.suber/phones/')
from app import app as application


