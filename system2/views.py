from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import ReceivedMessage
from .serializers import ReceivedMessageSerializer
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from system2.models import SentMessage
from .serializers import SentMessageSerializer
from .utils import decrypt_message, encrypt_message
import requests

# Sending messages
class SendMessageView(APIView):
    def post(self, request):
        message = request.data.get("message")
        user_id = request.data.get("user_id")
        token = request.headers.get("Authorization")
        
        if token and token.startswith("Bearer "):
            token = token.split("Bearer ")[1]
        else:
            token = request.data.get("token")  # Fallback to token in request body

        if not message or not user_id or not token:
            return Response({"error": "Message, user_id, and token are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Encrypt the message before sending it
        encrypted_message = encrypt_message(message)

        sent_message = SentMessage.objects.create(user=user, message=encrypted_message)

        system1_url = 'http://127.0.0.1:8001/api/system1/received/'
        payload = {
            'message': encrypted_message,  # Send the encrypted message
            'user_id': user_id
        }

        headers = {
            'Authorization': f'Bearer {token}'
        }

        try:
            response = requests.post(system1_url, json=payload, headers=headers)
            
            if response.status_code == 201:
                return Response({
                    "message": "Message sent and saved successfully",
                    "message_id": sent_message.id
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    "error": f"Failed to send message to System 1: {response.status_code} - {response.text}"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        except requests.exceptions.RequestException as e:
            print(f"Error sending message to System 1: {str(e)}")
            return Response({"error": "Failed to send message to System 1"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Receiving messages
class ReceiveMessageView(APIView):
    authentication_classes = [JWTAuthentication]  # Optional: Add if JWT authentication is required
    permission_classes = [IsAuthenticated]  # Optional: Only authenticated users can access

    def post(self, request):
        encrypted_message = request.data.get("message")
        user_id = request.data.get("user_id")

        if not encrypted_message or not user_id:
            return Response({"error": "Message and user_id are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Decrypt the received message
            decrypted_message = decrypt_message(encrypted_message)

            # Save the decrypted message in the database
            received_message = ReceivedMessage.objects.create(user_id=user_id, message=decrypted_message)

            return Response({
                "message": "Message received successfully",
                "message_id": received_message.id,
                "decrypted_message": decrypted_message  # For debugging
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            print(f"Error while saving or decrypting message: {e}")
            return Response({"error": "Failed to save or decrypt message"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        # Retrieve all received messages from the database
        received_messages = ReceivedMessage.objects.all()
        
        # Serialize the data
        serializer = ReceivedMessageSerializer(received_messages, many=True)

        # Return the serialized data
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class ViewSentMessagesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        messages = SentMessage.objects.filter(user=user)
        serializer = SentMessageSerializer(messages, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

# Home page
def home(request):
    return HttpResponse("Welcome to System 2 (Receiver)")

# Home page
def home(request):
    return HttpResponse("Welcome to the messaging system!")


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        email = request.data.get("email")

        if not username or not password:
            return Response({"error": "Username and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return Response({"error": "Username is already taken"}, status=status.HTTP_400_BAD_REQUEST)

        # Create the user
        user = User.objects.create_user(username=username, password=password, email=email)
        user.save()

        return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response({"error": "Username and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=username, password=password)

        if user is None:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }, status=status.HTTP_200_OK)