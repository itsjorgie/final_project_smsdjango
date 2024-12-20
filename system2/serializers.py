from rest_framework import serializers
from .models import ReceivedMessage, SentMessage

class ReceivedMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReceivedMessage
        fields = ['id', 'user_id', 'message', 'timestamp']  # Adjust fields as necessary

class SentMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = SentMessage
        fields = ['user', 'message', 'timestamp', 'message_type']