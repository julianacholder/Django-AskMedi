from django.core.mail import send_mail
from django.conf import settings

def send_otp_email(user):
    user.set_otp()
    subject = 'Your OTP for Ask Medi Registration'
    message = f'Your OTP is: {user.otp}. This OTP is valid for 5 minutes.'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [user.email]
    send_mail(subject, message, from_email, recipient_list)