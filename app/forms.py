# Flask modules
import bcrypt
from flask_wtf import FlaskForm
from sqlalchemy import Values
from wtforms.validators import ValidationError
from wtforms import IntegerField, StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp, NumberRange

# Local modules
from app.models import User, WatchTarget
from app.extensions import bcrypt

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'placeholder': 'example@email.com'})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'placeholder': '********'})
    remember_me = BooleanField('Remember me', default=False)
    submit = SubmitField('Log In')

class StripeSettingsEditForm(FlaskForm):
    stripe_public_key = StringField(
        'Stripe Public Key',
        validators=[
            DataRequired(),
        ],
        render_kw={'placeholder': 'Public Key'},
    )
    stripe_secret_key = StringField(
        'Stripe Secret Key',
        validators=[
            DataRequired(),
        ],
        render_kw={'placeholder': 'Secret Key'},
    )
    stripe_webhook_secret = StringField(
        'Stripe Webhook Secret',
        validators=[
            DataRequired(),
        ],
        render_kw={'placeholder': 'Stripe Webhook Secret'},
    )
    submit = SubmitField('Save')

class RegistrationForm(FlaskForm):
    name = StringField(
        'Name',
        validators=[
            DataRequired(),
            Length(min=2, max=80),
            Regexp(r'^[a-zA-Z0-9_. -]+$', message='Name must contain only letters, numbers, underscores, periods, spaces, and hyphens.')
        ],
        render_kw={'placeholder': 'Display name'}
    )
    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Email()
        ],
        render_kw={'placeholder': 'example@email.com'}
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=8),
        ],
        render_kw={'placeholder': 'Enter your password'}
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match')
        ],
        render_kw={'placeholder': 'Confirm your password'}
    )
    submit = SubmitField('Register')

    def validate_email(self, email):
        existing_user = User.query.filter_by(email=email.data).one_or_none()
        if existing_user:
            raise ValidationError('Email address already registered.')

    def validate_password(self, password):
        if not any(c.isalpha() for c in password.data) or not any(c.isdigit() for c in password.data):
            raise ValidationError('Password must contain at least one letter and one digit.')

class ProfileUpdateForm(FlaskForm):
    name = StringField(
        'Name',
        validators=[
            DataRequired(),
            Length(min=2, max=80),
            Regexp(r'^[a-zA-Z0-9_. -]+$', message='Name must contain only letters, numbers, and underscores.')
        ],
        render_kw={'placeholder': 'Display name'},
    )
    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Email()
        ],
        render_kw={'placeholder': 'example@email.com'}
    )
    password = PasswordField(
        'Current Password',
        validators=[
            DataRequired(),
            Length(min=8),
        ],
        render_kw={'placeholder': 'Enter your current password'}
    )
    new_password = PasswordField(
        'New Password',
        validators=[
            DataRequired(),
            Length(min=8),
        ],
        render_kw={'placeholder': 'Enter your new password'}
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(),
            EqualTo('new_password', message='Passwords must match')
        ],
        render_kw={'placeholder': 'Confirm your password'}
    )
    submit = SubmitField('Update')

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.old_user = user
        # print(user.name)
        # print(user.email)
        # self.name.default = user.name
        # self.email.default = user.email

    def validate_email(self, email):
        if email.data != self.old_user.email and User.query.filter_by(email=email.data).one_or_none():
            raise ValidationError('Email address already registered.')

    def validate_password(self, password):
        if not bcrypt.check_password_hash(self.old_user.password, password.data):
            raise ValidationError('Incorrect password.')

    def validate_new_password(self, new_password):
        if not any(c.isalpha() for c in new_password.data) or not any(c.isdigit() for c in new_password.data):
            raise ValidationError('Password must contain at least one letter and one digit.')

class WatchTargetAddForm(FlaskForm):
    tiktok_id = StringField(
        'Target TikTok ID',
        validators=[
            DataRequired(),
            Length(min=4, max=25),
            # Regexp(r'^@[a-zA-Z0-9_.]{3, 24}$', message='Begins with @ and contains 3 to 24 letters, numbers, underscores, periods, and hyphens.')
        ],
        render_kw={'placeholder': 'e.g., @isaackogan'},
    )
    ring1_goal = IntegerField(
        'Goal for Likes',
        validators=[
            DataRequired(),
            NumberRange(min=1, max=1000000000)
        ],
        render_kw={'placeholder': 'e.g, 100000'},
        default=100000
    )
    ring2_goal = IntegerField(
        'Goal for Shares',
        validators=[
            DataRequired(),
            NumberRange(min=1, max=1000000000)
        ],
        render_kw={'placeholder': 'e.g, 100'},
        default=100
    )
    ring3_goal = IntegerField(
        'Goal for Coins',
        validators=[
            DataRequired(),
            NumberRange(min=1, max=1000000000)
        ],
        render_kw={'placeholder': 'e.g, 150000'},
        default=150000
    )
    submit = SubmitField('Add')

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def validate_tiktok_id(self, tiktok_id):
        if tiktok_id.data[0] != '@':
            raise ValidationError('TikTok ID has to begin with @.')
        for c in tiktok_id.data[1:]:
            if c not in '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_.-':
                raise ValidationError('Invalid characters!')
        if WatchTarget.query.filter_by(tiktok_id=tiktok_id.data, client_id=self.user.id).one_or_none():
            raise ValidationError('TikTok ID already added.')

class WatchTargetEditForm(FlaskForm):
    ring1_goal = IntegerField(
        'Goal for Likes',
        validators=[
            DataRequired(),
            NumberRange(min=1, max=1000000000)
        ],
        render_kw={'placeholder': 'e.g, 100000'}
    )
    ring2_goal = IntegerField(
        'Goal for Shares',
        validators=[
            DataRequired(),
            NumberRange(min=1, max=1000000000)
        ],
        render_kw={'placeholder': 'e.g, 100'}
    )
    ring3_goal = IntegerField(
        'Goal for Coins',
        validators=[
            DataRequired(),
            NumberRange(min=1, max=1000000000)
        ],
        render_kw={'placeholder': 'e.g, 150000'}
    )
    submit = SubmitField('Save')

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

class ObserveClientForm(FlaskForm):
    email = StringField(
        'Client Email',
        validators=[
            DataRequired(),
            Email()
        ],
        render_kw={'placeholder': 'example@email.com'}
    )
    submit = SubmitField('Observe')

    def validate_email(self, email):
        if not User.query.filter_by(email=email.data).one_or_none():
            raise ValidationError('Cannot find such email.')

class SubscribeForm(FlaskForm):
    submit = SubmitField('Subscribe')
