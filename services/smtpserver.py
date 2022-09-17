import smtplib
from email.mime.text import MIMEText
import ssl

class mailServer:

    Subject: str = "Verification"
    To: str = ""
    Message: str = ""

    def sendlink(self):
        if self.To:
            msg = MIMEText(self.Message)
            msg['Subject'] = self.Subject
            msg['From'] = "gg.too.ez.kal@gmail.com"
            msg['To'] = self.To
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                server.login("gg.too.ez.kal@gmail.com", "zonakonoobispcif")
                server.sendmail("gg.too.ez.kal@gmail.com", self.To, msg.as_string())
                print("Successfully sent email")
        else:
            print("No one to send mail to")