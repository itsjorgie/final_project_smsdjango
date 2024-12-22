from django.urls import path
from .views import (
    home,
    SendMessageView,
    RegisterView,
    ViewSentMessagesView,
    ReceiveMessageView,
    LoginView,  # Import your custom LoginView
)

urlpatterns = [
    path('', home, name='home'),
    path('send/', SendMessageView.as_view(), name='send-message'),
    path('sent-messages/', ViewSentMessagesView.as_view(), name='view-sent-messages'),
     path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),  # Use your custom LoginView
    path('received/', ReceiveMessageView.as_view(), name='view-received-messages'),
]
