# Paid installation phase 2

V1 shows a payment preview and performs no checkout. Phase 2 must add ScriptBox identity/entitlements, server-calculated price/currency/tax/fees, Stripe, PayPal, Apitsoft bKash/Nagad, Tripay, Razorpay, and Wise adapters, signed idempotent webhooks, payment/refund/revocation/reinstall state, and entitlement/domain/license-bound authorization. Sessions stay server-side behind HttpOnly cookies; JavaScript payment cookies and client totals are forbidden.
