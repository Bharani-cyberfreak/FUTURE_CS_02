import pandas as pd
import re

emails = pd.read_csv("../dataset/emails.csv")

def classify_email(subject, sender, body):
    phishing_words = ["urgent", "verify", "password", "login", "account"]

    if re.search(r"http[s]?://", body):
        return "Phishing"
    elif any(word in subject.lower() for word in phishing_words):
        return "Suspicious"
    elif not sender.endswith("@trusted.com"):
        return "Phishing"
    else:
        return "Safe"

def awareness(subject, sender, body, result):
    print("Email Subject:", subject)
    print("Sender:", sender)
    print("Classification:", result)

    if result != "Safe":
        print("Reason:")
        if "http" in body:
            print("- Contains suspicious link")
        if not sender.endswith("@trusted.com"):
            print("- Sender domain looks fake")
        print("Prevention Tips:")
        print("1. Do not click unknown links")
        print("2. Verify sender email")
        print("3. Report phishing emails")
    print("-" * 50)

for _, row in emails.iterrows():
    result = classify_email(row['subject'], row['sender'], row['body'])
    awareness(row['subject'], row['sender'], row['body'], result)
