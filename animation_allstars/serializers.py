
from dataclasses import field
from lib2to3.pgen2 import token
from multiprocessing import AuthenticationError
import re
from rest_framework import serializers 
from. models import User, Ideas, Comment
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ValidationError
from uuid import uuid4
from django.db.models import Q 
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate
from datetime import datetime 
from datetime import datetime, date, time, timedelta
from datetime import timezone
import calendar
from datetime import datetime
from django.db.models import Q

class RegisterSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(max_length=60, min_length=6, write_only=True)
    last_name = serializers.CharField(max_length=60, min_length=6, write_only=True)
    birth_year = serializers.IntegerField()
    email = serializers.EmailField(
            required=True,
            validators=[UniqueValidator(queryset=User.objects.all())])
    password = serializers.CharField(max_length=60, min_length=6, write_only=True, required=True, validators=[validate_password])
    image_url = serializers.ImageField(required=False)
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'birth_year', 'password', 'email', 'image_url', "about_user"]
    
    def validate(self, attrs):
        lower_email = attrs.get('email', '')
        if User.objects.filter(email__iexact=lower_email).exists():
            raise serializers.ValidationError({'email', ("Email is alredy in use")})
        return super().validate(attrs)

    def create(self, validated_data):
        validated_data['first_name'] = validated_data['first_name']
        validated_data['last_name'] = validated_data['last_name']
        validated_data['birth_year'] = validated_data['birth_year']
        validated_data['password'] = make_password(validated_data['password'])
        validated_data['email'] = validated_data['email']
        validated_data['image_url'] = validated_data.get("image_url", "")
        return super(RegisterSerializer, self).create(validated_data)

class UserLoginSerializer(serializers.ModelSerializer):
    # to accept either username or email
    email = serializers.EmailField()
    password = serializers.CharField()
    tokens = serializers.CharField(required=False, read_only=True)
    
    class Meta:
        model = User
        fields = (
            'email',
            'password',
            'tokens',
        )

        read_only_fields = (
            'token',
        )

    def validate(self, data):
        # user,email,password validator
        email = data.get("email", None)
        password = data.get("password", None)
        users = authenticate(email=email, password=password)
        if not users:
            raise AuthenticationFailed("Invalid Credentials try Again")
        if not email and not password:
            raise ValidationError("Details not entered.")
        user = None
        # if the email has been passed
        obj=User.objects.get(email=email)
        if not obj.email_verified:
            raise ValidationError("Email is not Verified")
        pw=obj.password
        flag=check_password(password, pw)
        if not flag:
            raise ValidationError("User credentials are not correct.")
        if '@' in email:
            user = User.objects.filter(
                Q(email=email) &
                Q(password=pw)
                ).distinct()
            if not user.exists():
                raise ValidationError("User credentials are not correct.")
            user = User.objects.get(email=email)
        else:
            user = User.objects.filter(
                Q(email=email) &
                Q(password=pw)
            ).distinct()
            if not user.exists():
                raise ValidationError("User credentials are not correct.")
            user = User.objects.get(email=email)
        data['token'] = uuid4()
        user.token = data['token']
        user.save()
        return {"emai": users.email, "token": users.tokens}

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ["email"]

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ["password", "token", "uidb64"]

    def validate(self, attrs):

        try:
            password = attrs.get("password")
            token = attrs.get("token")
            uidb64 = attrs.get("uidb64")

            id = force_str(urlsafe_base64_decode(uidb64))
            user  = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)
            user.set_password(password)
            user.save()
            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super(SetNewPasswordSerializer, self).validate(attrs)

# class GenresSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Genres
#         fields = ['genre_name', 'genre_description']
    
#     def validate(self, data):
#         error_text_array = []
#         if data['genre_name'].strip() == "":
#             error_text_array.append("Please enter genre name")

#         if data['genre_description'].strip() == "":
#             error_text_array.append("Please enter genre description")
        
#         if error_text_array:
#             raise serializers.ValidationError({"error_text": error_text_array})

#         return data

# class FileExtensionSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = FileExtensions
#         fields = ['file_extension']
    
#     def validate(self, data):
#         error_text_array = []

#         if data['file_extension'].strip() == "":
#             error_text_array.append("Please enter file extension")
        
#         if error_text_array:
#             raise serializers.ValidationError({"error_text": error_text_array})

#         return data


# class UserIdeaSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = UserIdea
#         fields = ['user', 'genre', 'idea_description', 'file_url', 'file_extension']
#     def validate(self, attrs):
#         user = attrs['user']
#         count = UserIdea.objects.filter(user=user).count()
#         if count>3:
#             raise serializers.ValidationError({'Genres', ("User cannot add more than three genres")})
#         return super().validate(attrs)

def in_month_year(month, year):
    d_fmt = "{0:>02}.{1:>02}.{2}"
    date_from = datetime.strptime(
        d_fmt.format(1, month, year), '%d.%m.%Y').date()
    last_day_of_month = calendar.monthrange(year, month)[1]
    date_to = datetime.strptime(
        d_fmt.format(last_day_of_month, month, year), '%d.%m.%Y').date()
    return Ideas.objects.filter(
        Q(created_on__gte=date_from, created_on__lte=date_to) | Q(created_on__lt=date_from, created_on__gte=date_from))

class IdeasSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ideas
        fields = ['user', 'idea', 'idea_name', 'description', 'genre', 
                  'idea_description', 'file_url', 'file_extension']
        
    def validate(self, attrs):
        idea_id = attrs['user']
        mydt = datetime.now() - timedelta(1)
        mon = datetime.now().month
        yer = datetime.now().year
        test=in_month_year(mon,yer)
        day = Ideas.objects.filter(user=idea_id, created_on__gt=mydt).count()
        monthcount = test.count()
        if monthcount>=10:
            raise serializers.ValidationError({'Idea', ("cannot add more than ten ideas within one month")})
        elif day>=2:
            raise serializers.ValidationError({'Idea', ("cannot add more than two ideas within 24 hrs")})
        return super().validate(attrs)

class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ["users", "user_idea", "comment"]

# class PostlikeSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = PostLikes
#         fields = '__all__'

