from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import SentMessage
from .serializers import SentMessageSerializer
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.shortcuts import render
from django.shortcuts import redirect
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.contrib import messages  # For flashing success/error messages
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
import requests
from .utils import decrypt_message, encrypt_message
from .models import ReceivedMessage
from .serializers import ReceivedMessageSerializer




# Sending messages
class SendMessageView(APIView):
    def post(self, request):
        # Extract required data from the POST request
        message = request.data.get("message")
        user_id = request.data.get("user_id")
        token = request.headers.get("Authorization")

        # Extract Bearer token if available
        if token and token.startswith("Bearer "):
            token = token.split("Bearer ")[1]
        else:
            token = request.data.get("token")  # Fallback to token in request body

        # Validate inputs
        if not message or not user_id or not token:
            # Return error message in HTML
            return render(request, 'send_message_form.html', {
                'error': 'Message, user_id, and token are required'
            })

        # Check if the user exists
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return render(request, 'send_message_form.html', {
                'error': 'User not found'
            })

        # Encrypt the message
        try:
            encrypted_message = encrypt_message(message)
        except Exception as e:
            return render(request, 'send_message_form.html', {
                'error': f'Message encryption failed: {str(e)}'
            })

        # Save the encrypted message to the database
        sent_message = SentMessage.objects.create(user=user, message=encrypted_message)

        # Prepare payload for System 1
        system1_url = "http://127.0.0.1:8001/api/system1/received/"
        payload = {
            "message": encrypted_message,
            "user_id": user_id,
        }
        headers = {
            "Authorization": f"Bearer {token}",
        }

        # Send the message to System 1
        try:
            response = requests.post(system1_url, json=payload, headers=headers)

            if response.status_code == 201:
                # Return success message in HTML
                return render(request, 'send_message_form.html', {
                    'success': f'Message sent and saved successfully. Message ID: {sent_message.id}'
                })
            else:
                # Return failure message in HTML
                return render(request, 'send_message_form.html', {
                    'error': f'Failed to send message to System 1: {response.status_code} - {response.text}'
                })

        except requests.exceptions.RequestException as e:
            # Return error message in HTML for request failure
            return render(request, 'send_message_form.html', {
                'error': f'Failed to send message to System 1: {str(e)}'
            })
            
class ViewSentMessagesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        messages = SentMessage.objects.filter(user=user)
        serializer = SentMessageSerializer(messages, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

# Receiving messages
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
    
# Home page
def home(request):
    return HttpResponse("Welcome to the messaging system!")



class RegisterView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        """
        Render the registration page for GET requests.
        """
        return render(request, 'register.html')

    def post(self, request):
        """
        Handle registration functionality for POST requests.
        Supports both form-encoded data and JSON data for API use.
        """
        # Get registration data from either form or JSON
        username = request.data.get("username") or request.POST.get("username")
        password = request.data.get("password") or request.POST.get("password")
        confirm_password = request.data.get("confirm_password") or request.POST.get("confirm_password")
        email = request.data.get("email") or request.POST.get("email")

        # Validate input fields
        if not username or not password or not email or not confirm_password:
            if request.accepted_renderer.format == 'json':  # API response
                return Response(
                    {"error": "All fields (username, password, confirm password, and email) are required."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            else:  # HTML response
                messages.error(request, "All fields (username, password, confirm password, and email) are required.")
                return redirect('register')

        if password != confirm_password:
            if request.accepted_renderer.format == 'json':  # API response
                return Response(
                    {"error": "Passwords do not match."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            else:  # HTML response
                messages.error(request, "Passwords do not match.")
                return redirect('register')

        if User.objects.filter(username=username).exists():
            if request.accepted_renderer.format == 'json':  # API response
                return Response(
                    {"error": "Username is already taken."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            else:  # HTML response
                messages.error(request, "Username is already taken.")
                return redirect('register')

        if User.objects.filter(email=email).exists():
            if request.accepted_renderer.format == 'json':  # API response
                return Response(
                    {"error": "Email is already registered."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            else:  # HTML response
                messages.error(request, "Email is already registered.")
                return redirect('register')

        try:
            # Create the user
            user = User.objects.create_user(username=username, password=password, email=email)
            user.save()

            if request.accepted_renderer.format == 'json':  # API response
                return Response(
                    {"message": "Registration successful! Please login."},
                    status=status.HTTP_201_CREATED
                )
            else:  # HTML response
                messages.success(request, "Registration successful! Please login.")
                return redirect('login')  # Redirect to the login page after successful registration

        except Exception as e:
            if request.accepted_renderer.format == 'json':  # API response
                return Response(
                    {"error": f"Error occurred: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            else:  # HTML response
                messages.error(request, f"Error occurred: {str(e)}")
                return redirect('register')


class LoginView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        """
        Render the login page for GET requests.
        """
        return render(request, 'dashboard/login.html')  # Adjust the path as needed

    def post(self, request):
 
        """
        Handle login functionality for POST requests.
        Supports both JSON and form-encoded data.
        """
        username = request.data.get("username") or request.POST.get("username")
        password = request.data.get("password") or request.POST.get("password")

        if not username or not password:
            # Handle missing credentials
            if 'text/html' in request.META.get('HTTP_ACCEPT', ''):  # Browser request
                messages.error(request, "Username and password are required.")
                return render(request, 'dashboard/login.html')  # Show the login page again
            else:  # API request
                return Response(
                    {"error": "Username and password are required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # Authenticate the user
        user = authenticate(username=username, password=password)


        if user is None:
            # Handle invalid credentials
            if 'text/html' in request.META.get('HTTP_ACCEPT', ''):  # Browser request
                messages.error(request, "Invalid username or password. Please try again.")
                return render(request, 'dashboard/login.html')  # Show the login page again
            else:  # API request
                return Response(
                    {"error": "Invalid username or password."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        # Check if the request is from a browser (form submission)
        if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
            messages.success(request, "Login successful!")
            return redirect('send-message')  # Redirect to the send-message page

        # For API requests, return the tokens in JSON format
        return Response(
            {
                "message": "Login successful.",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                },
                "tokens": {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
            },
            status=status.HTTP_200_OK,
        )