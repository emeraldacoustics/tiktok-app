Clients can get real-time information about their interested TikTok Live users.

Available information are numbers of:
- Likes
- Shares
- Gifts (or diamonds)

Clients can subscribe via Stripe.

**The client's email must match their payment email.**

The following environment variables are required for installation.
- `SQLALCHEMY_DATABASE_URI`
- `DOMAIN_URL`
- `ADMIN_NAME`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `APP_PRICE_DAY`
- `APP_PRICE_WEEK`
- `APP_PRICE_MONTH`
- `APP_PRICE_YEAR`
- `STRIPE_PUBLIC_KEY`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `CONNECTED_ACCOUNT_ID`

The price values must be measured in cents.
