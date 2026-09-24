"""Train the CyberShield production text-classification model (TF-IDF + LogisticRegression).

Creates REAL trained artifacts for backend/app/ml/nlp_prod so the deployed
backend reports a trained-model tier instead of the keyword fallback. The
model is trained here from an original, in-repo labeled corpus written for
this project (SMS/chat/email-style scam, phishing, spam and benign texts) —
no third-party dataset is downloaded or redistributed.

Honesty rules:
  - Metrics in EVALUATION.txt are computed on a held-out stratified split of
    the real corpus. Nothing is fabricated.
  - The app still reports WHICH tier is live (roberta > trained > fallback)
    and never claims a tier that did not actually load.

Usage:
    python scripts/train_prod_nlp.py            # trains + writes artifacts
"""
from __future__ import annotations

import json
import os
import sys

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer

BACKEND = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND)

from app.core.config import settings  # noqa: E402

# ---------------------------------------------------------------------------
# Original labeled corpus (written for CyberShield). Language patterns mirror
# real-world SMS/chat/email threat categories; all texts are synthetic.
# ---------------------------------------------------------------------------
SAFE = [
    "Hey are we still meeting for coffee tomorrow at 10?",
    "Mom said dinner is at 7 tonight, don't be late.",
    "Can you send me the notes from today's lecture?",
    "The movie starts at 8, let's meet at the entrance.",
    "Happy birthday! Have a wonderful day celebrating.",
    "I'll call you after my meeting finishes around 4.",
    "Don't forget to bring the charger I lent you.",
    "The weather is lovely today, want to walk in the park?",
    "Thanks for helping me move the boxes last weekend.",
    "Practice is cancelled this Thursday, see you Monday.",
    "Did you watch the game last night? What a finish!",
    "My flight lands at 6, I'll text you from the airport.",
    "Please water the plants while I'm away this week.",
    "The doctor appointment is confirmed for Friday morning.",
    "Great presentation today, the team was impressed.",
    "Let's order pizza and catch up this weekend.",
    "Your library book is due back next Wednesday.",
    "The train was delayed but I'll still make it on time.",
    "Reminder: family lunch at grandma's on Sunday.",
    "I finished the report, feedback welcome before I send it.",
    "Are you free for a quick call this afternoon?",
    "The new cafe downtown has amazing pastries.",
    "Congratulations on the new job, so proud of you!",
    "School photos are next Tuesday, wear your uniform.",
    "Traffic is heavy, I might be 10 minutes late.",
    "Happy anniversary to you both, celebrating tonight!",
    "Could you pick up milk and bread on your way home?",
    "The wifi password is on the fridge magnet.",
    "See you at yoga class tomorrow evening.",
    "Your package was delivered to the front porch.",
    "Book club meets at Sarah's place this month.",
    "The community garage sale is on Saturday morning.",
    "I got tickets for the concert in October!",
    "Lunch was delicious, we should do it again soon.",
    "Can you recommend a good plumber? Our sink is leaking.",
    "The kids loved the zoo trip, thanks for organizing.",
    "My new number is 555-0142, save it please.",
    "The library extended opening hours on weekends now.",
    "Well done on passing your driving test!",
    "We're collecting for the local food bank this month.",
    "The neighborhood watch meeting moved to next Tuesday.",
    "Your prescription is ready for pickup at the pharmacy.",
    "Loved your photos from the hiking trip!",
    "The office will be closed on Monday for the holiday.",
    "Don't forget your umbrella, it's raining here.",
    "The tutor can move our session to Thursday if you like.",
    "Welcome to the team, see you at onboarding on Monday.",
    "Your membership renewal was processed successfully.",
    "The workshop was informative, slides are online.",
    "Merry Christmas and a happy new year to your family!",
]

SPAM = [
    "Win a brand new smartwatch! Reply YES to claim your free gift now!",
    "Congratulations! You've been selected for a free holiday voucher. Click to claim!",
    "Get 90% off designer watches today only. Shop now!",
    "You are our 1000th visitor! Claim your prize immediately.",
    "Exclusive deal just for you! Free starter kit with any subscription.",
    "Claim your free ringtone pack now, limited downloads available!",
    "New customers get a free tablet with any plan. Sign up today!",
    "You have won a lottery ticket bonus! Reply CLAIM to receive.",
    "Flash sale: 75% off everything for the next 2 hours!",
    "Earn money from home, no experience needed! Sign up free.",
    "Your entry in our monthly draw was upgraded to VIP. Claim now!",
    "Free trial of premium streaming for 30 days, activate now!",
    "Get the newest smartphone for half price this weekend only!",
    "You've earned 500 reward points! Redeem before they expire.",
    "Subscribe now and get your first month completely free.",
    "Limited offer: buy one get two free on all accessories!",
    "Unbeatable insurance rates, switch today and save hundreds.",
    "Your favorite store has a secret sale, unlock with this code.",
    "Complete our survey and receive a gift card instantly!",
    "Double your data allowance at no extra cost, upgrade now!",
    "Referral bonus: invite friends and get cash rewards!",
    "Clearance blowout: everything must go, prices slashed!",
    "You qualify for a premium credit card with zero fees!",
    "Unlock exclusive discounts by joining our VIP club free.",
    "New weight loss miracle, results guaranteed in days!",
    "Get paid to watch videos, start earning today!",
    "Your loyalty points are expiring, redeem them for gifts now!",
    "Special upgrade offer: faster internet for the same price!",
    "Win concert tickets by sharing our page with friends!",
    "Free warranty extension available, register your device now.",
    "Limited spots for free online courses, enroll today!",
    "Cashback boost weekend: 10% extra on everything!",
    "Our biggest sale of the year starts right now!",
    "You're pre-approved for a loan up to $50,000!",
    "Test and keep the latest gadget, apply in 2 minutes!",
    "Save on energy bills with our free switch service!",
    "Exclusive preview access for valued customers like you!",
    "Get a free month of meal delivery, cancel anytime!",
    "Your table is booked! Confirm your free dessert upgrade.",
    "Join thousands winning daily prizes, it's free to enter!",
    "Back in stock! The item you wanted is 40% off today.",
    "Mobile plan upgrade: unlimited calls for less!",
    "Enter our photo contest and win professional equipment!",
    "Free e-book download this week only, grab your copy!",
    "Mystery discount unlocked: spin the wheel to reveal!",
]

SCAM = [
    "URGENT: Your bank account has been suspended due to suspicious activity. Verify your identity immediately.",
    "Your account will be permanently locked within 24 hours unless you confirm your password now.",
    "We detected unusual login attempts. Confirm your credentials via this link to secure your account.",
    "Your debit card has been blocked. Update your card details immediately to restore access.",
    "Final warning: pay the outstanding fine within 12 hours or a warrant will be issued.",
    "Your electricity will be cut off today. Pay the bill now through the link to avoid disconnection.",
    "IRS notice: unpaid taxes detected. Settle immediately to avoid legal action and arrest.",
    "Your package is held at customs. Pay the release fee to receive your delivery.",
    "You missed your court date. Pay the processing fee now to cancel the arrest warrant.",
    "Your mobile banking is disabled. Restore access by verifying your PIN and account number.",
    "Bank security alert: someone tried to access your account from abroad. Verify your identity NOW.",
    "Your subscription payment failed. Update your billing information to avoid suspension.",
    "Parcel delivery failed: unpaid shipping fee required. Pay now to reschedule delivery.",
    "Your credit score dropped dramatically. Verify your SSN to review the report.",
    "This is the final notice for your unpaid invoice. Pay within 2 hours or face legal consequences.",
    "Your email storage is full. Confirm your password to upgrade your quota for free.",
    "Fraudulent charge detected on your card. Confirm your CVV to cancel the transaction.",
    "Your loan application is approved! Send the processing fee to release the funds.",
    "Your account earned a refund of $250. Provide your bank details to receive the payout.",
    "Payment declined: verify your card number within one hour or your account will be closed.",
    "Your insurance policy expires today. Renew immediately with your card details.",
    "We locked your online profile due to policy violations. Unlock by confirming your phone number.",
    "Government benefit claim pending: verify your identity with your national ID number.",
    "Your vehicle registration is revoked. Pay the reinstatement fee now to avoid penalties.",
    "Your medical insurance is inactive. Confirm your payment information to reactivate coverage.",
]

PHISHING = [
    "Your account requires immediate verification: http://secure-verify.tk/login",
    "PayPal: unusual activity detected. Confirm your identity at http://paypal-alert.tk/verify",
    "Netflix payment declined. Update your billing at http://netflix-billing.xyz/renew",
    "Amazon: your account is locked. Sign in at http://amazon-security.top/unlock",
    "Your bank statement is ready: view at http://chase-online.xyz/documents",
    "Microsoft account suspicious sign-in: http://microsoft-verify.click/secure",
    "Apple ID disabled due to security reasons: http://appleid-locked.top/unlock",
    "IRS tax refund approved: claim at http://irs-refund.xyz/claim",
    "Wells Fargo alert: verify your phone number at http://wf-security.tk/confirm",
    "DHL: your shipment is on hold, pay customs at http://dhl-parcel.xyz/fees",
    "Google: security alert from new device. Review at http://google-alerts.top/check",
    "Your flight refund is processed: http://airline-refunds.xyz/claim",
    "Instagram: copyright violation, appeal at http://insta-support.tk/appeal",
    "LinkedIn: your job offer letter is ready at http://career-offers.xyz/offer",
    "WhatsApp will be deactivated: verify at http://whatsapp-verify.top/reactivate",
    "Coinbase: unauthorized login attempt. Secure wallet at http://coinbase-alert.xyz/lock",
    "Steam: your account was reported. Respond at http://steam-support.top/appeal",
    "Your SSN was used in a crime nearby: report at http://ssa-alert.xyz/report",
    "HBO Max subscription expired: http://hbomax-renew.xyz/billing",
    "Facebook marketplace sale payout pending: http://fb-payouts.xyz/receive",
    "Office 365 password expiring today: http://o365-reset.xyz/password",
    "Snapchat support: your account needs age verification http://snap-verify.top/age",
    "FedEx delivery exception: reschedule at http://fedex-redeliver.xyz/schedule",
    "Chase bank: new device sign-in detected http://chase-secure.tk/approve",
    "Warranty expired for your vehicle: extend at http://auto-warranty.xyz/extend",
    "Bank of America: card temporarily frozen http://bofa-alerts.top/unfreeze",
    "Spotify premium won in our draw: claim at http://spotify-prize.xyz/win",
    "Your package could not be delivered: http://usps-redelivery.xyz/track",
    "Zoom account suspended for unusual activity: http://zoom-secure.top/restore",
    "E-billing invoice overdue: view at http://invoice-portal.xyz/pay",
    "Roblox free robux generator: http://rbx-rewards.top/claim",
    "Bank transfer of $1,250 is waiting: http://transfer-alert.xyz/accept",
    "HMRC tax rebate eligibility check: http://hmrc-rebates.xyz/apply",
    "Your SIM card will be deactivated: http://sim-verify.top/confirm",
    "UNICEF donation receipt: download at http://charity-receipts.xyz/receipt",
]

# ---------------------------------------------------------------------------
DATA = [(t, "SAFE") for t in SAFE] + [(t, "SPAM") for t in SPAM] \
     + [(t, "SCAM") for t in SCAM] + [(t, "PHISHING") for t in PHISHING]
LABELS = ["SAFE", "SPAM", "SCAM", "PHISHING"]


def main() -> None:
    texts = [t for t, _ in DATA]
    labels = [l for _, l in DATA]
    assert len(texts) == len(set(texts)), "duplicate training texts found"

    Xtr, Xte, ytr, yte = train_test_split(
        texts, labels, test_size=0.2, stratify=labels, random_state=42)

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1)),
        ("clf", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")),
    ])
    pipe.fit(Xtr, ytr)

    ypred = pipe.predict(Xte)
    report = classification_report(yte, ypred, labels=LABELS, zero_division=0)
    cm = confusion_matrix(yte, ypred, labels=LABELS)
    cv = cross_val_score(pipe, texts, labels, cv=5)

    model_dir = os.path.join(BACKEND, "app", "ml", "nlp_prod")
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(pipe, os.path.join(model_dir, "model.joblib"))
    with open(os.path.join(model_dir, "labels.json"), "w") as f:
        json.dump({"labels": LABELS}, f)
    with open(os.path.join(model_dir, "EVALUATION.txt"), "w") as f:
        f.write("CyberShield production NLP — TF-IDF + LogisticRegression\n")
        f.write("Corpus: original in-repo labeled texts (%d samples, %d classes)\n"
                % (len(texts), len(LABELS)))
        f.write("Held-out split: 20%% stratified (n=%d)\n\n" % len(yte))
        f.write(report + "\n")
        f.write("Confusion matrix (rows=true, cols=pred, order %s):\n" % LABELS)
        f.write(np.array2string(cm) + "\n\n")
        f.write("5-fold CV accuracy: %.3f ± %.3f\n" % (cv.mean(), cv.std()))
        f.write("\nHonest limits: trained on synthetic patterns for this project;\n"
                "not a substitute for a large-scale fine-tuned transformer.\n")

    print(report)
    print("5-fold CV accuracy: %.3f ± %.3f" % (cv.mean(), cv.std()))
    print("Saved artifacts to", model_dir)
    print("Include EVALUATION.txt — metrics above are real, computed on held-out data.")


if __name__ == "__main__":
    main()
