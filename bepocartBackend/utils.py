from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
import random
import requests
from django.core.cache import cache
from django.conf import settings

def send_order_email(order):
    subject = f"New Order Received: {order.id}"
    from_email = settings.EMAIL_HOST_USER
    recipient_list = ['contact@bepocart.com']

    # Render the HTML template with the order context
    html_content = render_to_string('order_email.html', {'order': order})

    # Create an EmailMultiAlternatives object
    email = EmailMultiAlternatives(
        subject=subject,
        body='This is an HTML email. Please use an email client that supports HTML.',
        from_email=from_email,
        to=recipient_list,
    )
    
    # Attach the HTML content
    email.attach_alternative(html_content, "text/html")

    # Send the email 
    email.send()





def generate_otp():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def store_otp(phone_number, otp):
    """Store OTP in cache with a 5-minute expiration."""
    cache.set(phone_number, otp, timeout=300)


def send_otp(phone_number, otp):
    sms_alert_username = 'francisgoskates@gmail.com'  # Replace with your actual SMSAlert username
    sms_alert_password = 'xdr5IBU@'  # Replace with your actual SMSAlert password
    sms_alert_sender_id = 'BECART'  # Replace with your actual Sender ID
    template_id = '1707162624837116051'



    message = f'Your verification code for login to Bepocart is {otp}'

    url = 'https://www.smsalert.co.in/api/push.json'

    payload = {
        'user': sms_alert_username,
        'pwd': sms_alert_password,
        'sender': sms_alert_sender_id,
        'mobileno': phone_number,
        'text': message,
        'template_id': template_id,
    }
    

    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()  # Raises HTTPError for bad responses
        response_data = response.json()

        if response_data.get('status') == 'success':
            return True
        else:
            return False
    except requests.exceptions.HTTPError as e:
        return False
    except requests.exceptions.RequestException as e:
        return False