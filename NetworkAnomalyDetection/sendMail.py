import smtplib, ssl
from email.message import EmailMessage
from bs4 import BeautifulSoup
import requests
from datetime import date
import time

def sendAlert(attack):
    
    sender_email = "ruhullahansari88@gmail.com"
    receiver_email = "np01nt4s210035@islingtoncollege.edu.np"
    password = "pijxnwisgfdtohhg"

    subject = "Network Anomaly Detected"
    body = """\
    Attack Type: %s.""" % (attack)

    em = EmailMessage()

    em['From'] = sender_email
    em['To'] = receiver_email
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, em.as_string())
        print("Mail Sent")
