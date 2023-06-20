#!/usr/bin/env python3
from flask import Flask, abort, request, jsonify, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, decode_token
import urllib
from datetime import date
import json
import base64
import os
from email.message import EmailMessage
import ssl
import smtplib


# POLYGON
from polygon import RESTClient
import config
from typing import cast
from urllib3 import HTTPResponse
client = RESTClient(config.API_KEY)
aggs = cast(
    HTTPResponse,
    client.get_aggs(
        'AAPL',
        1,
        'day',
        '2023-03-10',
        '2023-05-25',
        raw=True
    )
)
data = json.loads(aggs.data)
print([key['c'] for key in data['results']])
 
#
#   Naming conventions: (https://realpython.com/python-pep8/)
#
#   Function/Method: lowercase, underscores (function, my_function)
#   Class: capital first letter, pascal casing (Model, MyClass)
#   Constant: uppercase, underscores (CONSTANT, MY_CONSTANT)
#

# Initierande av app och moduler
app = Flask(__name__, template_folder='../client/templates', static_folder='../client')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "OQEIROFZMNVZNDVFFJIASE"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Catch-all router till hemsidan
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
    return render_template("index.html")



#
#   HTTPS
#

@app.route('/https/positions/<int:account_id>', methods=['GET', 'POST'])
def events(account_id):
    return jsonify({test:'test'})


#
#   DB-MODELLER
#

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email= db.Column(db.String, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    portfolio = db.relationship('Position', backref='owner', lazy=True, foreign_keys = 'Position.owner')
    transactions = db.relationship('Transaction', backref='owner', lazy=True, foreign_keys='Transaction.owner')
    moderator = db.Column(db.Boolean, nullable=False, default=False)
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf8')
    
    def __repr__(self):
        return '<Account {}: {}'.format(self.id, self.email)
    
    def seralize(self):
        return dict(id=self.id, email=self.email, moderator=self.moderator)

class Position(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.Integer, db.ForeignKey('Account.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=date.today())
    quantity = db.Column(db.Integer, nullable=False)
    aprice = db.Column(db.Float, nullable=False)


if __name__ == "__main__":
    app.run(port=5001, debug=True) # På MacOS, byt till 5001 eller dylikt
    
    