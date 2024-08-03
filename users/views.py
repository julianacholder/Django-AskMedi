from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.shortcuts import get_object_or_404
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .serializers import UserSerializer
from .models import CustomUser, VerificationToken
from .serializers import UserSerializer
from .utils import send_otp_email
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from .models import UserSummary
from .serializers import UserSummarySerializer
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from .authentication import CsrfExemptSessionAuthentication
from rest_framework.authentication import BasicAuthentication


class StoreSummaryAndDiagnosisView(APIView):
   
    authentication_classes = [] 
    permission_classes = [AllowAny] 

    def post(self, request):
        serializer = UserSummarySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Summary and diagnosis stored successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class GetSummariesView(APIView):
    authentication_classes = [] 
    permission_classes = [AllowAny]
    def get(self, request, user_id):
        summaries = UserSummary.objects.filter(user_id=user_id)
        serializer = UserSummarySerializer(summaries, many=True)
        return Response(serializer.data)

class RegisterView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save(is_active=False)  
            send_otp_email(user)
            return Response({"message": "User registered. Check your email for OTP.", "email": user.email}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        try:
            user = CustomUser.objects.get(email=email)
            if user.otp == otp and user.is_otp_valid():
                user.is_active = True
                user.is_verified = True  
                user.otp = None
                user.otp_created_at = None
                user.save()
                return Response({"message": "OTP verified successfully. You can now log in."}, status=status.HTTP_200_OK)
            return Response({"message": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

class ResendOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = CustomUser.objects.get(email=email)
            if user.otp_created_at and (timezone.now() - user.otp_created_at).total_seconds() < 30:
                return Response({"message": "Please wait 30 seconds before requesting a new OTP"}, status=status.HTTP_400_BAD_REQUEST)
            send_otp_email(user)
            return Response({"message": "New OTP sent"}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class LoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request, username=email, password=password)
        if user is not None:
            if user.is_verified:
                login(request, user)
                token, _ = Token.objects.get_or_create(user=user)
                return Response({"message": "Login successful", "token": token.key}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Please verify your email before logging in"}, status=status.HTTP_403_FORBIDDEN)
        return Response({"message": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        logout(request)
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)

class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, token):
        verification_token = get_object_or_404(VerificationToken, token=token)
        user = verification_token.user
        user.is_verified = True
        user.save()
        verification_token.delete()
        return Response({"message": "Email verified successfully"}, status=status.HTTP_200_OK)

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')

        if not user.check_password(old_password):
            return Response({"message": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_password(new_password, user)
        except ValidationError as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        update_session_auth_hash(request, user)

        return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
    
class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        print(request.user)
        if request.user.is_authenticated:
            serializer = UserSerializer(request.user)
            return Response(serializer.data)
        else:
            return Response({"message": "User is not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)
