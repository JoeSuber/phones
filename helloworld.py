from flask import Flask
import os

app = Flask(__name__)


@app.route('/')
def index():
    with open(os.path.join(os.getcwd(), "test.txt"), 'wb') as fob:
        fob.write("Hey I think this is a file")
    return "<h1> HELOOoooo </h1>"

if __name__ == "__main__":
    app.run()