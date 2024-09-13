from communityapp.models import *
from rest_framework import serializers
from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.conf import settings
# from django.utils.translation import ugettext_lazy as _
#from django.utils.translation import gettext as _
from rest_framework import serializers, exceptions
from rest_framework.exceptions import ValidationError
from allauth.account import app_settings
from dj_rest_auth.serializers import PasswordResetSerializer


UserModel = get_user_model()
class CustomLoginRoleSerializer(serializers.Serializer):
    username = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(style={'input_type': 'password'})
    role    = serializers.IntegerField()
  
    print("custom user login")
    def authenticate(self, **kwargs):
        return authenticate(self.context['request'], **kwargs)

    def _validate_email(self, email, password):
        user = None
        print("CustomLoginRoleSerializer _validate_email ")
        if email and password:
            user = self.authenticate(email=email, password=password)
        else:
            msg = _('Must include "email" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def _validate_username(self, username, password):
        user = None
        print("CustomLoginRoleSerializer _validate_username ")
        if username and password:
            user = self.authenticate(username=username, password=password)
        else:
            msg = _('Must include "username" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def _validate_username_email(self, username, email, password):
        user = None
        print("CustomLoginRoleSerializer _validate_username_email ")
        if email and password:
            user = self.authenticate(email=email, password=password)
        elif username and password:
            user = self.authenticate(username=username, password=password)
        else:
            msg = _('Must include either "username" or "email" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def validate(self, attrs):
        print("CustomLoginRoleSerializer validate ")
        username = attrs.get('username')
        email = attrs.get('email')
        password = attrs.get('password')
        role = attrs.get('role')

        print(attrs.get('role'))

        user = None

        if 'allauth' in settings.INSTALLED_APPS:
            from allauth.account import app_settings
            print("app_settings.AUTHENTICATION_METHOD: ",app_settings.AUTHENTICATION_METHOD)

            # Authentication through email
            if app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.EMAIL:
                user = self._validate_email(email, password)

            # Authentication through username
            elif app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.USERNAME:
                user = self._validate_username(username, password)

            # Authentication through either username or email
            else:
                user = self._validate_username_email(username, email, password)
            # print("user from allauth :",user)
        else:
            # Authentication without using allauth
            if email:
                try:
                    username = UserModel.objects.get(email__iexact=email).get_username()
                except UserModel.DoesNotExist:
                    pass

            if username:
                user = self._validate_username_email(username, '', password)
            # print("user from allauth else: :",user)
        # Did we get back an active user?
        
        if user:
            if not user.is_active:
                msg = _('User account is disabled or user is not authorized.')
                raise exceptions.ValidationError(msg)
        else:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)
        if user:
            print("User Role is",user.role)
            if  user.role != role:
                msg = _('User account is not authorized to use this portal.')
                raise exceptions.ValidationError(msg)
        else:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)

        # If required, is the email verified?
        if 'rest_auth.registration' in settings.INSTALLED_APPS:
            
            if app_settings.EMAIL_VERIFICATION == app_settings.EmailVerificationMethod.MANDATORY:
                email_address = user.emailaddress_set.get(email=user.email)
                if not email_address.verified:
                    raise serializers.ValidationError(_('E-mail is not verified.'))

        attrs['user'] = user
        return attrs

class UserModelSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    extra_kwargs = {'password': {'write_only': True}}
    fields = [
      "id",
      "name",
      "username",
      "email",
      "password",
      "role",
    ]

  def create(self, validated_data):
    user = UserModel.objects.create_user(
      validated_data["username"],
      validated_data["email"],  
      validated_data["password"]
    )

    return user