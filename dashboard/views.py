from django.shortcuts import render
from system1.models import SentMessage
from system2.models import ReceivedMessage

# Create your views here.

def dashboard_view(request):
    sent_messages = SentMessage.objects.all()
    received_messages = ReceivedMessage.objects.all()

    return render(request, 'dashboard/dashboard.html', {
        'sent_messages': sent_messages,
        'received_messages': received_messages
    })
