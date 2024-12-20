from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import SentMessage
from .serializers import SentMessageSerializer
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
import requests
from .models import ReceivedMessage
from .serializers import ReceivedMessageSerializer

# Sending messages
class SendMessageView(APIView):
    def post(self, request):
        # Get the message, user, and token from the request
        message = request.data.get("message")
        user_id = request.data.get("user_id")

        # Retrieve the token from the request headers or body
        token = request.headers.get("Authorization")
        if token and token.startswith("Bearer "):
            token = token.split("Bearer ")[1]
        else:
            token = request.data.get("token")  # Fallback to token in request body

        if not message or not user_id or not token:
            return Response({"error": "Message, user_id, and token are required"}, status=status.HTTP_400_BAD_REQUEST)

        # Find the user
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Save the message to System 1 SentMessage
        sent_message = SentMessage.objects.create(user=user, message=message)

        # Send the message to System 2 via an HTTP POST request
        system2_url = 'http://127.0.0.1:8002/api/system2/received/'  # Replace with System 2's URL
        payload = {
            'message': message,
            'user_id': user_id
        }

        headers = {
            'Authorization': f'Bearer {token}'  # Include the user-provided token in the Authorization header
        }

        try:
            response = requests.post(system2_url, json=payload, headers=headers)

            # Debugging logs to check response
            print(f"Response from System 2: {response.status_code} - {response.text}")
            
            if response.status_code == 201:
                return Response({
                    "message": "Message sent and saved successfully",
                    "message_id": sent_message.id
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    "error": f"Failed to send message to System 2: {response.status_code} - {response.text}"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        except requests.exceptions.RequestException as e:
            # Log if there's an error with the HTTP request
            print(f"Error sending message to System 2: {str(e)}")
            return Response({"error": "Failed to send message to System 2"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ViewSentMessagesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        messages = SentMessage.objects.filter(user=user)
        serializer = SentMessageSerializer(messages, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

# Receiving messages
class ReceiveMessageView(APIView):
    authentication_classes = [JWTAuthentication]  # Optional: Add if JWT authentication is required
    permission_classes = [IsAuthenticated]  # Optional: Only authenticated users can access

    def post(self, request):
        # Log the request data for debugging purposes
        print("Received request data:", request.data)

        # Extract the message and user_id from the request
        message = request.data.get("message")
        user_id = request.data.get("user_id")

        if not message or not user_id:
            return Response({"error": "Message and user_id are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Save the received message in the database
            received_message = ReceivedMessage.objects.create(user_id=user_id, message=message)

            # Return a success response
            return Response({
                "message": "Message received successfully",
                "message_id": received_message.id,
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            # Log exception for debugging
            print(f"Error while saving message: {e}")
            return Response({"error": "Failed to save message"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        # Retrieve all received messages from the database
        received_messages = ReceivedMessage.objects.all()
        
        # Serialize the data
        serializer = ReceivedMessageSerializer(received_messages, many=True)

        # Return the serialized data
        return Response(serializer.data, status=status.HTTP_200_OK)

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