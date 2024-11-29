from django.core.mail import EmailMessage
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings

def send_order_status_email(order):
    """
    Send an HTML email to the customer notifying them of the order status update.
    """
    subject = f"Order #{order.pk} Status Updated"
    context = {
        'customer': order.customer,
        'order_id': order.pk,
        'status': order.status
    }
    message = render_to_string('order_status_email.html', context)
    
    try:
        email = EmailMessage(
            subject,
            message,
            settings.EMAIL_HOST_USER,  # Make sure this is set in your settings
            [order.customer.email]
        )
        email.content_subtype = "html"  # Important for sending HTML content
        email.send(fail_silently=False)
    except Exception as e:
        # Log the exception or handle it accordingly
        print(f"Error sending email: {str(e)}")

        

def send_order_email(order):
    subject = f"New Order Received: {order.order_id}"
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
    email





