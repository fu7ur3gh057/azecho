from celery import shared_task
from celery.utils.log import get_task_logger
from django.core.mail import EmailMessage
from constants import CELERY_PRIORITY

logger = get_task_logger(__name__)


@shared_task(name='send_email_task', priority=CELERY_PRIORITY['EMAIL'])
def send_email_task(data):
    logger.info(f'email data :: {data}')
    subject = data['email_subject']
    body = data['email_body']
    receivers = [data['receivers']]
    email = EmailMessage(subject=subject, body=body, to=receivers)
    email.send()
