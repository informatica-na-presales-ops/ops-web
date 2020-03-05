import email.message
import logging
import ops_web.config
import smtplib

log = logging.getLogger(__name__)


def send_email(c: ops_web.config.Config, to_addr, subject, body) -> bool:
    log.info(f'Sending email to {to_addr}')
    if c.send_email:
        msg = email.message.EmailMessage()
        msg['X-SES-CONFIGURATION-SET'] = c.aws_ses_configuration_set
        msg['Subject'] = subject
        msg['From'] = c.smtp_from
        msg['To'] = to_addr
        msg.set_content(body, subtype='html')
        with smtplib.SMTP_SSL(host=c.smtp_host) as s:
            s.login(user=c.smtp_username, password=c.smtp_password)
            try:
                s.send_message(msg)
            except smtplib.SMTPRecipientsRefused as e:
                log.error(f'{e}')
                return False
    else:
        log.warning(f'Not sending email to {to_addr}\n{body}')
    return True
