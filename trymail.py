import smtplib

sender = 'joe.suber@dvtandc.com'
receivers = ['support@contegix.com', 'joe.suber@dvtandc.com']

for receiver in receivers:
    message = """From: <{}>
    To: <{}>
    Subject: SMTP e-mail test
    
    This is a test e-mail message that hopefully works now and won't end up in spam
    """.format(sender, receiver)

    try:
       smtpObj = smtplib.SMTP('localhost')
       smtpObj.sendmail(sender, receiver, message)
       print("Successfully sent email")
    except smtplib.SMTPException:
       print("Error: unable to send email")
