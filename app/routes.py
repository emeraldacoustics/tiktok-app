# Flask modules
from calendar import month
import datetime
from flask import Blueprint, Response, jsonify, redirect, request, url_for, render_template, flash
from flask_login import login_user, logout_user, current_user, login_required
import os
import json
from flask_migrate import current
from flask import Flask

import stripe
import datetime
from dateutil.relativedelta import relativedelta

# Local modules
from app.models import User, WatchTarget, Setting, PaymentRecord
from app.extensions import db, bcrypt, login_manager
from app.forms import LoginForm, ProfileUpdateForm, RegistrationForm, StripeSettingsEditForm, WatchTargetAddForm, WatchTargetEditForm, SubscribeForm, ObserveClientForm

app = Flask(
    __name__,
    template_folder='../templates',
    static_folder='../static',
    static_url_path='/'
)

def get_setting_value(key: str):
    item = db.session.query(Setting).filter_by(key=key).one_or_none()
    if item:
        return item.value
    else:
        return None

def set_setting_value(key: str, value: str):
    item = db.session.query(Setting).filter_by(key=key).one_or_none()
    if item:
        item.value = value
    else:
        item = Setting(
            key=key,
            value=value
        )
        db.session.add(item)
    db.session.commit()

def get_app_price_month():
    return get_setting_value('APP_PRICE_MONTH')

def set_app_price_month(value: str):
    return set_setting_value('APP_PRICE_MONTH', value)

def get_app_price_year():
    return get_setting_value('APP_PRICE_YEAR')

def set_app_price_year(value: str):
    return set_setting_value('APP_PRICE_YEAR', value)

def get_stripe_public_key():
    return get_setting_value('STRIPE_PUBLIC_KEY')

def set_stripe_public_key(value: str):
    return set_setting_value('STRIPE_PUBLIC_KEY', value)

def get_stripe_secret_key():
    return get_setting_value('STRIPE_SECRET_KEY')

def set_stripe_secret_key(value: str):
    return set_setting_value('STRIPE_SECRET_KEY', value)

def get_stripe_webhook_secret():
    return get_setting_value('STRIPE_WEBHOOK_SECRET')

def set_stripe_webhook_secret(value: str):
    return set_setting_value('STRIPE_WEBHOOK_SECRET', value)

def get_connected_account_id():
    return get_setting_value('CONNECTED_ACCOUNT_ID')

def set_connected_account_id(value: str):
    return set_setting_value('CONNECTED_ACCOUNT_ID', value)

def user_has_not_expired(id: int):
    user = db.session.query(User).filter_by(id=id).one_or_none()
    if user:
        now = datetime.datetime.now(datetime.UTC)
        return now.date() <= user.expiration_date.date()
    else:
        return None

def add_user(name: str, email: str, password: str, is_admin: bool=False):
    user: User
    if is_admin:
        user = db.session.query(User).filter_by(email=email).one_or_none()
        if not user:
            user = User(
                name=name,
                email=email,
                password=password,
                stripe_customer_id="adm",
                is_admin=is_admin,
            )
            db.session.add(user)
            db.session.commit()
    else:
        customers = stripe.Customer.list(email=email)
        customer: stripe.Customer
        if customers.data and ('deleted' not in customers.data[0] or not customers.data[0].deleted):
            customer = customers.data[0]
        else:
            customer = stripe.Customer.create(
                name=name,
                email=email,
            )

        user = db.session.query(User).filter_by(email=email).one_or_none()
        if not user:
            user = User(
                name=name,
                email=email,
                password=password,
                stripe_customer_id=customer.id,
                is_admin=is_admin,
            )
            db.session.add(user)
            db.session.commit()
        else:
            user.stripe_customer_id = customer.id
            db.session.commit()
    return user

def update_user(id: int, name: str, email: str, password: str):
    user = User.query.get(current_user.id)
    user.name = name
    user.email = email
    user.password = password
    if not user.is_admin:
        stripe.Customer.modify(
            id=user.stripe_customer_id,
            name=name,
            email=email,
        )
    db.session.commit()

    return user

def get_tiktok_app_product():
    product: stripe.Product = None
    last_prod = None
    while True:
        if last_prod:
            products = stripe.Product.list(starting_after=last_prod)
        else:
            products = stripe.Product.list()
        
        for prod in products.data:
            last_prod = prod.id
            if prod.name=="TikTok App":
                product = prod
                break

        if product:
            break

        if not products.has_more:
            break

    if not product:
        product = stripe.Product.create(name="TikTok App")

        day_price = stripe.Price.create(
            product=product.id,
            unit_amount=50,
            currency='usd',
            recurring={"interval": "day"},
            lookup_key="day",
        )

        week_price = stripe.Price.create(
            product=product.id,
            unit_amount=300,
            currency='usd',
            recurring={"interval": "week"},
            lookup_key="week",
        )

        month_price = stripe.Price.create(
            product=product.id,
            unit_amount=int(get_app_price_month()) * 100,
            currency='usd',
            recurring={"interval": "month"},
            lookup_key="month",
        )

        year_price = stripe.Price.create(
            product=product.id,
            unit_amount=int(get_app_price_year()) * 100,
            currency='usd',
            recurring={"interval": "year"},
            lookup_key="year",
        )
    
    return product

def get_day_price():
    product = get_tiktok_app_product()
    day_price = stripe.Price.search(query=f"product:\"{product.id}\" AND lookup_key:\"day\"").data[0]
    return day_price

def get_week_price():
    product = get_tiktok_app_product()
    week_price = stripe.Price.search(query=f"product:\"{product.id}\" AND lookup_key:\"week\"").data[0]
    return week_price

def get_month_price():
    product = get_tiktok_app_product()
    month_price = stripe.Price.search(query=f"product:\"{product.id}\" AND lookup_key:\"month\"").data[0]
    return month_price

def get_year_price():
    product = get_tiktok_app_product()
    year_price = stripe.Price.search(query=f"product:\"{product.id}\" AND lookup_key:\"year\"").data[0]
    return year_price

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).one_or_none()

@app.route("/")
def home():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('routes.admin_home'))
        else:
            return redirect(url_for('routes.client_home'))
    else:
        return redirect(url_for("routes.login"))

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("routes.home"))

    form = RegistrationForm()

    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.generate_password_hash(password)

        # Add user to database
        new_user = add_user(
            name=name,
            email=email,
            password=hashed_password
        )
        # new_user = User(name=name, email=email, password=hashed_password)
        # db.session.add(new_user)
        # db.session.commit()

        # Login user
        login_user(new_user)

        flash(f'Account created successfully! You are now logged in as {new_user.name}.', 'success')
        return redirect(url_for("routes.home"))

    return render_template('auth/register.html', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("routes.home"))

    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        remember_me = form.remember_me.data

        user = User.query.filter_by(email=email).one_or_none()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=remember_me)
            flash(f"Logged in successfully as {user.name}", 'success')
            return redirect(url_for("routes.home"))
        else:
            flash("Invalid email or password", 'danger')

    return render_template('auth/login.html', form=form)

@app.route("/profile_update", methods=['GET', 'POST'])
@login_required
def profile_update():
    user = User.query.get(current_user.id)
    form = ProfileUpdateForm(user)

    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        new_password = form.new_password.data

        # Update user
        update_user(user.id, name, email, bcrypt.generate_password_hash(new_password))
        # user.name = name
        # user.email = email
        # user.password = bcrypt.generate_password_hash(new_password)
        # db.session.commit()

        # Login user
        logout_user()
        login_user(user)

        flash(f'Account created successfully! You are now logged in as {user.name}.', 'success')
        return redirect(url_for("routes.home"))

    return render_template('auth/profile_update.html', form=form, user=user)

@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for("routes.login"))

@app.route("/admin")
@login_required
def admin_home():
    if current_user.is_admin:
        clients = db.session.query(User).filter_by(is_admin=False)
        return render_template('admin/index.html', clients=clients)
    else:
        return redirect(url_for("routes.login"))

@app.route("/admin/observe")
@login_required
def admin_observe():
    if current_user.is_admin:
        return redirect(url_for('routes.admin_observe_client', id=current_user.id))
    else:
        flash("You don't have admin privilidges", 'failed')
        return redirect(url_for("routes.client_home"))

@app.route("/admin/observe/<int:id>", methods=['GET', 'POST'])
@login_required
def admin_observe_client(id):
    if current_user.is_admin:
        form = ObserveClientForm()
        if form.validate_on_submit():
            email = form.email.data
            client = db.session.query(User).filter_by(email=email).one_or_none()
            if client:
                return redirect(url_for('routes.admin_observe_client', id=client.id))

        client = db.session.query(User).filter_by(id=id).one_or_none()
        targets = db.session.query(WatchTarget).filter_by(client_id=id).all()
        return render_template('admin/observe.html', client=client, targets=targets, form=form)
    else:
        flash("You don't have admin privilidges", 'failed')
        return redirect(url_for("routes.client_home"))

@app.route("/admin/payments")
@login_required
def admin_payments():
    if current_user.is_admin:
        payment_records = db.session.query(PaymentRecord).order_by(PaymentRecord.timestamp.desc()).all()
        return render_template('admin/payments.html', payment_records=payment_records)
    else:
        flash("You don't have admin privilidges", 'failed')
        return redirect(url_for("routes.client_home"))

@app.route("/admin/stripe_settings", methods=['GET', 'POST'])
@login_required
def admin_stripe_settings():
    if not current_user.is_admin:
        flash("You don't have admin privilidges", 'failed')
        return redirect(url_for("routes.client_home"))

    form = StripeSettingsEditForm()

    if form.validate_on_submit():
        stripe_public_key = form.stripe_public_key.data
        stripe_secret_key = form.stripe_secret_key.data
        stripe_webhook_secret = form.stripe_webhook_secret.data

        set_stripe_public_key(stripe_public_key)
        set_stripe_secret_key(stripe_secret_key)
        set_stripe_webhook_secret(stripe_webhook_secret)
        stripe.api_key = stripe_secret_key

        flash(f"Stripe settings saved", 'success')
        return redirect(url_for("routes.home"))

    return render_template(
        'admin/stripe_settings.html',
        form=form,
        stripe_public_key=get_stripe_public_key(),
        stripe_secret_key=get_stripe_secret_key(),
        stripe_webhook_secret=get_stripe_webhook_secret(),
    )

@app.route("/client")
@login_required
def client_home():
    if current_user.is_admin:
        return redirect(url_for("routes.admin_home"))

    targets = WatchTarget.query.filter_by(client_id=current_user.id).all()

    return render_template('client/index.html', targets=targets)

@app.route("/client/subscribe")
@login_required
def client_subscribe():
    if current_user.is_admin:
        return redirect(url_for("routes.admin_home"))

    month_form = SubscribeForm()
    year_form = SubscribeForm()

    return render_template('client/subscribe.html', month_form=month_form, year_form=year_form)

@app.route("/client/subscribe/<plan>", methods=['POST'])
@login_required
def client_subscribe_plan(plan):
    if current_user.is_admin:
        return redirect(url_for("routes.admin_home"))

    month_form = SubscribeForm()
    year_form = SubscribeForm()

    if plan == 'month' and month_form.validate_on_submit():
        try:
            session = stripe.checkout.Session.create(
                line_items=[{
                    'price': get_month_price().id,
                    'quantity': 1,
                    'adjustable_quantity': {
                        'enabled': False,
                    }
                }],
                mode='subscription',
                success_url=(os.getenv('DOMAIN_URL') + '/client/subscribe/success/month/{CHECKOUT_SESSION_ID}'),
                cancel_url=(os.getenv('DOMAIN_URL') + '/client/subscribe/cancel/month/{CHECKOUT_SESSION_ID}'),
                automatic_tax={
                    'enabled': True
                },
            )
            return redirect(session.url, code=303)
        except Exception as e:
            return jsonify(error=str(e)), 403
    elif plan == 'year' and year_form.validate_on_submit():
        try:
            session = stripe.checkout.Session.create(
                line_items=[{
                    'price': get_year_price().id,
                    'quantity': 1,
                    'adjustable_quantity': {
                        'enabled': False,
                    }
                }],
                mode='subscription',
                success_url=(os.getenv('DOMAIN_URL') + '/client/subscribe/success/year/{CHECKOUT_SESSION_ID}'),
                cancel_url=(os.getenv('DOMAIN_URL') + '/client/subscribe/cancel/year/{CHECKOUT_SESSION_ID}'),
                automatic_tax={
                    'enabled': True
                },                
            )
            return redirect(session.url, code=303)
        except Exception as e:
            return jsonify(error=str(e)), 403

    return redirect(url_for("routes.client_subscribe"))
    return render_template('client/subscribe.html', month_form=month_form, year_form=year_form)

@app.route("/client/payments")
@login_required
def client_payments():
    if current_user.is_admin:
        return redirect(url_for("routes.admin_home"))

    payment_records = db.session.query(PaymentRecord).filter_by(client_id=current_user.id).order_by(PaymentRecord.timestamp.desc()).all()

    return render_template('client/payments.html', payment_records=payment_records)

@app.route("/client/subscribe/success/<plan>/<checkout_session_id>")
@login_required
def client_subscribe_success_plan(plan, checkout_session_id):
    if plan == 'month':
        session = stripe.checkout.Session.retrieve(checkout_session_id)
        if session:
            client = db.session.query(User).filter_by(email=session.customer_details.email).one_or_none()
            items = stripe.checkout.Session.list_line_items(checkout_session_id)
            if client and client.id==current_user.id:
                client.expiration_date = max(client.expiration_date, datetime.datetime.now(datetime.UTC)) + relativedelta(months=items.data[0].quantity)
                db.session.add(PaymentRecord(
                    client_id=client.id,
                    plan=plan,
                    amount=items.data[0].quantity,
                    expiration_date=client.expiration_date,
                    checkout_session_id=checkout_session_id,
                ))
                db.session.commit()
                flash("Successfully subscribed", "success")
        return redirect(url_for('routes.client_payments'))
    elif plan == 'year':
        session = stripe.checkout.Session.retrieve(checkout_session_id)
        if session:
            client = db.session.query(User).filter_by(email=session.customer_details.email).one_or_none()
            items = stripe.checkout.Session.list_line_items(checkout_session_id)
            if client and client.id==current_user.id:
                client.expiration_date = max(client.expiration_date, datetime.datetime.now(datetime.UTC)) + relativedelta(years=items.data[0].quantity)
                db.session.add(PaymentRecord(
                    client_id=client.id,
                    plan=plan,
                    amount=items.data[0].quantity,
                    expiration_date=client.expiration_date,
                    checkout_session_id=checkout_session_id,
                ))
                db.session.commit()
                flash("Successfully subscribed", "success")
        return redirect(url_for('routes.client_payments'))
    else:
        return redirect(url_for('routes.client_subscribe'))

@app.route("/client/subscribe/cancel/<plan>/<checkout_session_id>")
@login_required
def client_subscribe_cancel_plan(plan, checkout_session_id):
    if plan == 'month':
        print("Cancel: " + checkout_session_id)
        return redirect(url_for('routes.client_subscribe'))
    else:
        return redirect(url_for('routes.client_subscribe'))

# @app.route("/webhook", methods=['POST'])
# def webhook():
#     payload = request.get_data()
#     signature = request.headers.get('stripe-signature')
#     stripe_webhook_secret = get_stripe_webhook_secret()

#     # Verify webhook signature and extract the event.
#     # See https://stripe.com/docs/webhooks/signatures for more information.
#     try:
#         event = stripe.Webhook.construct_event(
#             payload=payload,
#             sig_header=signature,
#             secret=stripe_webhook_secret
#         )
#     except ValueError as e:
#         # Invalid payload.
#         print(e)
#         return Response(status=400)
#     except stripe.error.SignatureVerificationError as e:
#         # Invalid Signature.
#         print(e, signature, stripe_webhook_secret, payload)
#         return Response(status=400)

#     if event.type == "checkout.session.completed":
#         session = event["data"]["object"]
#         # print(session)
#         # handle_checkout_session(event.account, session)
#     elif event.type == "checkout.session.completed":
#         session = event["data"]["object"]
#         connected_account_id = event.account
#         print(session)
#         # handle_checkout_session(connected_account_id, session)
#     elif event.type == "checkout.session.async_payment_succeeded":
#         session = event["data"]["object"]
#         connected_account_id = event.account

#         # client = db.session.query(User).filter_by(stripe_customer_id=session.customer).one_or_none()
#         # if client:
#         #     client.expiration_date = max(client.expiration_date, datetime.datetime.now(datetime.UTC)) + relativedelta(months=1)
#         #     db.session.commit()
#         print(session)
#         # handle_checkout_session(connected_account_id, session)
#     elif event.type == "checkout.session.async_payment_failed":
#         session = event["data"]["object"]
#         connected_account_id = event.account
#         print(session)
#         # handle_checkout_session(connected_account_id, session)

#     return json.dumps({"success": True}), 200

@app.route("/client/watchtarget_add", methods=['GET', 'POST'])
@login_required
def client_watchtarget_add():
    if current_user.is_admin:
        flash("Only clients can add watch targets", 'failed')
        return redirect(url_for("routes.home"))
    
    user = User.query.get(current_user.id)
    form = WatchTargetAddForm(user)

    if form.validate_on_submit():
        tiktok_id = form.tiktok_id.data
        ring1_goal = form.ring1_goal.data
        ring2_goal = form.ring2_goal.data
        ring3_goal = form.ring3_goal.data
        watchTarget = WatchTarget(
            tiktok_id=tiktok_id,
            client_id=current_user.id,
            ring1_goal=ring1_goal,
            ring2_goal=ring2_goal,
            ring3_goal=ring3_goal
        )

        db.session.add(watchTarget)
        db.session.commit()

        return redirect(url_for('routes.client_home'))

    return render_template('client/watchtarget_add.html', form=form)

@app.route("/client/watchtarget_edit/<int:id>", methods=['GET', 'POST'])
@login_required
def client_watchtarget_edit(id):
    if current_user.is_admin:
        flash("Administrator cannot delete the user's data", 'failed')
        return redirect(url_for("routes.admin_home"))

    watchTarget = WatchTarget.query.filter_by(id=id).one_or_none()
    if watchTarget:
        if watchTarget.client_id != current_user.id:
            flash("You cannot delete other client's watch target", 'failed')
            return redirect(url_for('routes.client_home'))
    else:
        flash("No such target or multiple targets exist", 'failed')
        return redirect(url_for('routes.client_home'))

    user = User.query.get(current_user.id)
    form = WatchTargetEditForm(user)
    if form.validate_on_submit():
        watchTarget.ring1_goal = form.ring1_goal.data
        watchTarget.ring2_goal = form.ring2_goal.data
        watchTarget.ring3_goal = form.ring3_goal.data
        db.session.commit()

        return redirect(url_for('routes.client_home'))

    return render_template('client/watchtarget_edit.html', form=form, target=watchTarget)

@app.route("/client/watchtarget_delete/<int:id>")
@login_required
def client_watchtarget_delete(id):
    if current_user.is_admin:
        flash("Administrator cannot delete the user's data", 'failed')
        return redirect(url_for("routes.admin_home"))

    watchTarget = WatchTarget.query.filter_by(id=id).one_or_none()
    if watchTarget:
        if watchTarget.client_id != current_user.id:
            flash("You cannot delete other client's watch target", 'failed')
            return redirect(url_for('routes.client_home'))
        db.session.delete(watchTarget)
        db.session.commit()
    else:
        flash("No such target or multiple targets exist", 'failed')
        return redirect(url_for('routes.client_home'))

    return redirect(url_for('routes.client_home'))
