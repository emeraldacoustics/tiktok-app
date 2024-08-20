# Flask modules
from flask import Flask
import stripe
import os
from random import randrange
from app.models import User, WatchTarget, Setting
from app import routes
from app.testdata import testdata_db

def create_app(debug: bool = False) -> Flask:    
    # Initialize app
    app = Flask(__name__, template_folder='../templates', static_folder='../static', static_url_path='/')

    # Setup app configs
    app.config['DEBUG'] = debug
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')

    # Initialize extensions
    from app.extensions import db, bcrypt, csrf, login_manager
    db.init_app(app)
    csrf.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    # Create database tables
    from app import models
    with app.app_context():

        db.create_all()

        if not routes.get_app_price_month():
            routes.set_app_price_month(os.getenv('APP_PRICE_MONTH'))

        if not routes.get_app_price_year():
            routes.set_app_price_year(os.getenv('APP_PRICE_YEAR'))

        if not routes.get_stripe_public_key():
            routes.set_stripe_public_key(os.getenv('STRIPE_PUBLIC_KEY'))

        if not routes.get_stripe_secret_key():
            routes.set_stripe_secret_key(os.getenv('STRIPE_SECRET_KEY'))
        stripe.api_key = routes.get_stripe_secret_key()

        print(os.getenv('STRIPE_WEBHOOK_SECRET'))
        if not routes.get_stripe_webhook_secret():
            routes.set_stripe_webhook_secret(os.getenv('STRIPE_WEBHOOK_SECRET'))

        if not routes.get_connected_account_id():
            routes.set_connected_account_id(os.getenv('CONNECTED_ACCOUNT_ID'))

        if len(db.session.query(User).filter_by(is_admin=True).all()) == 0:
            routes.add_user(
                name=os.getenv('ADMIN_NAME'),
                email=os.getenv('ADMIN_EMAIL'),
                password=bcrypt.generate_password_hash(os.getenv('ADMIN_PASSWORD')),
                is_admin=True
            )
            # db.session.add(
            #     User(
            #         name=os.getenv('ADMIN_NAME'),
            #         email=os.getenv('ADMIN_EMAIL'),
            #         password=bcrypt.generate_password_hash(os.getenv('ADMIN_PASSWORD')),
            #         is_admin=True
            #     )
            # )
            # db.session.commit()

        if len(User.query.filter_by(is_admin=False).all()) == 0:
            for user in testdata_db['user']:
                routes.add_user(
                    name=user['name'],
                    email=user['email'],
                    password=bcrypt.generate_password_hash(os.getenv('ADMIN_PASSWORD')),
                    is_admin=False
                )
            #     db.session.add(
            #         User(
            #             name=user['name'],
            #             email=user['email'],
            #             password=bcrypt.generate_password_hash(os.getenv('ADMIN_PASSWORD')),
            #             is_admin=False
            #         )
            #     )
            # db.session.commit()
        
        if len(WatchTarget.query.all()) == 0:
            for watchTarget in testdata_db['watch_target']:
                db.session.add(
                    WatchTarget(
                        tiktok_id=watchTarget['tiktok_id'],
                        client_id=watchTarget['client_id'],
                        # ring1_score=randrange(0, watchTarget['ring1_goal'] + 1),
                        ring1_goal=watchTarget['ring1_goal'],
                        # ring2_score=randrange(0, watchTarget['ring2_goal'] + 1),
                        ring2_goal=watchTarget['ring2_goal'],
                        # ring3_score=randrange(0, watchTarget['ring3_goal'] + 1),
                        ring3_goal=watchTarget['ring3_goal'],
                    )
                )
            db.session.commit()

    # Register blueprints
    from app.routes import routes_bp
    app.register_blueprint(routes_bp)

    return app
