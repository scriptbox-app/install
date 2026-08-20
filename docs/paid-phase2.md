# Paid installation phase 2

## Current public behavior

Version 1 may display paid applications, currencies, gateway names, and a payment preview. It does not create a payment session, charge a user, authorize a paid artifact, or install a paid package. Any interface suggesting otherwise is a defect and should be reported.

## Requirements before paid installation can launch

- ScriptBox user identity and durable entitlement binding.
- Server-calculated price, currency, tax, discounts, and fees; browser totals are never authoritative.
- Reviewed adapters for Stripe, PayPal, Apitsoft bKash/Nagad, Tripay, Razorpay, and Wise.
- Signed, authenticated, idempotent webhooks with replay protection.
- An explicit state machine for pending, paid, failed, expired, refunded, disputed, and revoked payments.
- Domain/license/entitlement-bound artifact authorization.
- Reinstallation limits, domain transfer, refunds, revocation, and failure recovery.
- HttpOnly server-side payment sessions; JavaScript payment cookies and local-storage tokens are forbidden.
- Privacy, PCI/payment-provider scope, retention, incident response, audit, and customer-support documentation.

## Security principle

The UI is a display and input layer. Prices, entitlements, payment state, and download authorization must be calculated and enforced by trusted servers. A successful browser redirect is never proof of payment.

Paid installation remains disabled until these contracts, threat models, tests, and operator procedures are complete.
