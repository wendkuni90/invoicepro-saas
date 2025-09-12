from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User, UserSession

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "role", "email_verified", "is_2fa_enabled"]

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "role", "phone"]

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            role=validated_data.get("role", User.Role.COMPANY_ADMIN),
            phone=validated_data.get("phone", None),
        )
        # email_verified = False par défaut
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(email=data["email"], password=data["password"])
        if not user:
            raise serializers.ValidationError("Identifiants invalides")
        if not user.is_active:
            raise serializers.ValidationError("Compte désactivé")
        return user

class VerifyEmailSerializer(serializers.Serializer):
    token = serializers.CharField()

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField()

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()

class TwoFASerializer(serializers.Serializer):
    token = serializers.CharField()

class UserSessionSerializer(serializers.ModelSerializer):
    current = serializers.SerializerMethodField()

    class Meta:
        model = UserSession
        fields = ["session_id", "ip_address", "user_agent", "device_name",
                    "created_at", "last_activity", "revoked", "current"]

    def get_current(self, obj):
        request = self.context.get("request")
        return str(obj.session_id) == request.COOKIES.get("session_id")
