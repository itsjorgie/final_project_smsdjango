from django.urls import path, include
from system2 import views
from .views import RegisterView, home, ReceiveMessageView, ViewSentMessagesView, SendMessageView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('', home, name='home'),
    path('send/', SendMessageView.as_view(), name='send-message'),
    path('sent-messages/', ViewSentMessagesView.as_view(), name='view-sent-messages'),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('received/', ReceiveMessageView.as_view(), name='view-received-messages'),
]
