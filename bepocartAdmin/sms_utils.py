import requests
from django.conf import settings

def send_order_status_sms(phone_number, order_id, status):
    """
    Send order status update via SMS using SMSAlert API.
    """
    url = "https://www.smsalert.co.in/api/push.json"
    payload = {
        "apikey": settings.SMSALERT_API_KEY,  # Your API key from SMSAlert
        "sender": settings.SMSALERT_SENDER_ID,  # Your sender ID
        "mobileno": phone_number,  # Recipient's phone number
        "text": f"Your order #{order_id} status has been updated to '{status}'.",  # Message content
        "reference": order_id,  # Unique reference for the message
        "dlrurl": "http://example.com/delivery_report"  # Optional URL for delivery reports
    }
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        response = requests.post(url, data=payload, headers=headers)
        response.raise_for_status()  # Raises HTTPError for bad responses (4xx and 5xx)
        
        response_data = response.json()
        if response_data.get("status") == "success":
            return True
        else:
            print(f"Failed to send status update SMS: {response_data.get('message')}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"Exception occurred while sending status update SMS: {str(e)}")
        return False
