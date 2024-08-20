# Flask modules
from time import timezone
from flask_login import UserMixin

# Other modules
import datetime

# Local modules
from app.extensions import db


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    plan = db.Column(db.String(80), nullable=False, default="N/A")
    stripe_customer_id = db.Column(db.String(80), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    created_date = db.Column(db.DateTime(timezone=True), default=datetime.datetime.now(datetime.UTC))
    expiration_date = db.Column(db.DateTime(timezone=True), default=datetime.datetime.now(datetime.UTC))

    def __repr__(self):
        return f'<User {self.name}>'

class WatchTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    tiktok_id = db.Column(db.String(255), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ring1_score = db.Column(db.Integer, nullable=False, default=0)
    ring1_goal = db.Column(db.Integer, nullable=False)
    ring2_score = db.Column(db.Integer, nullable=False, default=0)
    ring2_goal = db.Column(db.Integer, nullable=False)
    ring3_score = db.Column(db.Integer, nullable=False, default=0)
    ring3_goal = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"Client <{self.client_id}> is tracking <{self.tiktok_id}>"

class PaymentRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    plan = db.Column(db.String(255), nullable=False)
    # amount = db.Column(db.Integer, nullable=False, default=1)
    expiration_date = db.Column(db.DateTime)
    note = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime(timezone=True), default=datetime.datetime.now(datetime.UTC))

    def __repr__(self):
        return f"Client <{self.client_id}>'s payment will expire at <{self.expiration_date}>"

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    key = db.Column(db.String(255), nullable=False)
    value = db.Column(db.String(255))

    def __repr__(self):
        return f"<{self.key}>: <{self.value}>"

__all__ = [User, WatchTarget, PaymentRecord, Setting]
