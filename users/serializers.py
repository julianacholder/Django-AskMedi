from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import UserSummary

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])

    class Meta:
        model = User
        fields = ('id', 'email', 'fullname', 'gender', 'age', 'password')
        extra_kwargs = {
            'email': {'required': True},
            'fullname': {'required': True},
            'gender': {'required': True},
            'age': {'required': True},
        }

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['email'],
            email=validated_data['email'],
            fullname=validated_data['fullname'],
            gender=validated_data['gender'],
            age=validated_data['age'],
            password=validated_data['password']
        )
        return user
    
class UserSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSummary
        fields = ['id', 'user_id', 'summary_content', 'diagnosis_content', 'timestamp']