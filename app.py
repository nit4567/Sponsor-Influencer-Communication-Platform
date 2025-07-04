from flask import Flask

app = Flask(__name__)

from config import config
import models
import routes

if __name__=='__main__':
    app.run(debug=True)