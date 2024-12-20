from rest_framework import serializers
from .models import SentMessage, ReceivedMessage

class SentMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = SentMessage
        fields = ['user', 'message', 'timestamp', 'message_type']

class ReceivedMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReceivedMessage
        fields = ['id', 'user_id', 'message', 'timestamp']  # Adjust fields as necessary
