import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

sender = 'joe.suber@dvtandc.com'
receivers = ['joe.suber@dvtandc.com']

for receiver in receivers:
    message = """From: Joe <{}> \r\n
    To: Testees <{}> \r\n
    Subject: SMTP e-mail test \r\n
    
    This is a test e-mail message that hopefully works now and won't end up in spam.
    """.format(sender, receiver)

    try:
       smtpObj = smtplib.SMTP('localhost')
       smtpObj.sendmail(sender, [receiver], message)
       print("Successfully sent email")
    except smtplib.SMTPException:
       print("Error: unable to send email")
