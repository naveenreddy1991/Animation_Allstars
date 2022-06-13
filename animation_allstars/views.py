from ast import Expression
import re
from django.shortcuts import render
from rest_framework import generics, status
from .serializers import (IdeasSerializer, RegisterSerializer, 
                          UserLoginSerializer, 
                          ResetPasswordEmailRequestSerializer, 
                          SetNewPasswordSerializer, 
                          IdeasSerializer,
                          CommentSerializer)
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import permissions
from .models import Comment, User, Ideas
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
import jwt
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTP
from django.shortcuts import get_object_or_404
from django.db.models import Count
from .constants import custom_messages
# from rest_framework.generics import UpdateAPIView

def sendemailforforgotpassword(token, email_id):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Animation Allstars password reset"
    SERVER = "localhost"
    FROM = "noreply@rokit.com"
    TO = [email_id]
    # SUBJECT = "Forgot Password"
    # encoded_email = urllib.parse.quote(email_id.encode('utf8'))
    # dynamic_html = '<a href="https://dev-reset.club.rokit.com/'+token+'/?email='+encoded_email+'">https://dev-reset.club.rokit.com/'+token+'/?email='+encoded_email+'</a>'
    # html = '<p>A unique link to reset your password has been generated for you. To reset your password, click the following link and follow the instruction. <p>'+dynamic_html+' </p>'
    body = token

    part1=MIMEText(body, 'plain')

    msg.attach(part1)

    # Send the mail
    server = SMTP(SERVER)
    server.sendmail(FROM, TO, msg.as_string())
    server.quit()

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    # permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.data
        serilizer = self.serializer_class(data=user)
        if serilizer.is_valid(raise_exception=True):
            # serilizer.is_valid(raise_exception=True)
            serilizer.save()

            user_data = serilizer.data
            user = User.objects.get(email=user_data['email'])
            token = RefreshToken.for_user(user).access_token
            refresh_token = RefreshToken.for_user(user)
            relative_link = reverse('verify-email')
            current_site = get_current_site(request).domain
            absurl = 'http://'+current_site+relative_link+"?token="+str(token)
            email_body = "Hi "+user.first_name+" Use link below to verify your email \n"+absurl
            data = {'email_body': email_body, 'to_mail': user.email, 'email_subject': "Verify your email"}
            tokens = {"refresh": str(refresh_token), "acess": str(token)}
            # Util.send_mail(data)
            sendemailforforgotpassword(email_body, user.email)
            message = custom_messages.get("user_register_success")
            return Response({"message": message}, status=status.HTTP_201_CREATED)
        message = custom_messages.get("user_register_failure")
        return Response({'message':message},serilizer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmail(generics.GenericAPIView):
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.email_verified:
                user.email_verified = True
                user.save()
            message = custom_messages.get("verify_mail_success")
            return Response({"message":message}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            message = custom_messages.get("verify_mail_link_expired")
            return Response({'message':message}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            message = custom_messages.get("verify_mail_invalid_token")
            return Response({'message: message'}, status=status.HTTP_400_BAD_REQUEST)

# class LoginView(generics.GenericAPIView):
#     # get method handler
#     queryset = User.objects.all()
#     serializer_class = UserLoginSerializer
#     def post(self, request, *args, **kwargs):
#         serializer_class = UserLoginSerializer(data=request.data)
#         if serializer_class.is_valid(raise_exception=True):
#             return Response(serializer_class.data, status=status.HTTP_200_OK)
#         return Response(serializer_class.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(generics.GenericAPIView):
    queryset = User.objects.all()
    serializer_class = UserLoginSerializer
    def post(self, request, *args, **kwargs):
        data = request.data
        email = data.get("email", "")
        password = data.get("password", "")
        user = authenticate(request, username=email, password=password)
        if user:
            serializer_class = UserLoginSerializer(data=request.data)
            if serializer_class.is_valid(raise_exception=True):
                auth_token  = jwt.encode({'email': user.email}, settings.JWT_SECRET_KEY)
                serializer = UserLoginSerializer(user)
                data = {
                    'user': serializer.data
                }
                message = custom_messages.get("login_success")
                return Response({'message':message, 'data':data}, status=status.HTTP_200_OK)
        message = custom_messages.get("login_invalid_credentials")
        return Response({'message': message}, status=status.HTTP_401_UNAUTHORIZED)

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        email=request.data['email']
        if User.objects.filter(email=email).exists():
            user =  User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            # token = RefreshToken.for_user(user).access_token
            relative_link = reverse('password-reset-confirm', kwargs={"uidb64":uidb64, 'token':token})
            current_site = get_current_site(request=request).domain
            absurl = 'http://'+current_site+relative_link
            email_body = "Hell \n Use link below to reset password \n" + absurl
            sendemailforforgotpassword(email_body, email)
            # data = {'email_body': email_body, 'to_mail': user.email, 'email_subject': "Reset your password"}
            # Util.send_mail(data)
            message = custom_messages.get("request_pw_resset_susccess")
            return Response({"message":message}, status=status.HTTP_200_OK)
        message = custom_messages.get("request_pw_resset_email_not_found")
        return Response({"message":message}, status=status.HTTP_404_NOT_FOUND)

class PasswordTokenCheckApi(generics.GenericAPIView):

    def get(self, request, uidb64, token):
        
        try:
            id = smart_bytes(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
            # if not user and token:
                message = custom_messages.get("pw_resset_token_invalid")
                return Response({'message':message}, status=status.HTTP_401_UNAUTHORIZED)
            message = custom_messages.get("pw_token_check_success")
            return Response({"message":message, "success":"Credentials are valid", "uidb64":uidb64, "token":token}, status=status.HTTP_200_OK)
            
        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user):
                message = custom_messages.get("pw_resset_token_invalid")
                return Response({'message':message}, status=status.HTTP_401_UNAUTHORIZED)

class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    def patch(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        message = custom_messages.get("set_new_pw_success")
        return Response({"message":message}, status=status.HTTP_200_OK)

# class UserIdeaViewAPI(generics.GenericAPIView):   
#     """
#     API endpoint that allows users to be viewed or edited.
#     """
#     serializer_class = UserIdeaSerializer
#     # permission_classes = [IsAuthenticated]

#     def post(self, request):
#         data=request.data
#         user = data.get("user")
#         serializer = self.serializer_class(data=data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         auth_token  = jwt.encode({'email': user}, settings.JWT_SECRET_KEY)
#         return Response({"data":serializer.data,"token":auth_token},  status=status.HTTP_200_OK)

# class GenersViewAPI(generics.GenericAPIView):   
#     """
#     API endpoint that allows users to be viewed or edited.
#     """
#     serializer_class = GenresSerializer
#     # permission_classes = [IsAuthenticated]
#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         return Response(serializer.data, status=status.HTTP_200_OK)

# class FileExtensionViewAPI(generics.GenericAPIView):   
#     """
#     API endpoint that allows users to be viewed or edited.
#     """
#     serializer_class = FileExtensionSerializer
#     # permission_classes = [IsAuthenticated]
#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         return Response(serializer.data, status=status.HTTP_200_OK)

class IdeasViewAPI(generics.GenericAPIView):   
    """
    """
    serializer_class = IdeasSerializer
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        message = custom_messages.get("add_idea")
        return Response({'message':message}, status=status.HTTP_200_OK)

class CommentAPIView(generics.GenericAPIView):   
    """
    """
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]
    def post(self, request, *args, **kwargs):
        serializer_class = CommentSerializer(data=request.data)
        if serializer_class.is_valid(raise_exception=True):
            serializer_class.save()
            message = custom_messages.get("user_comment")
            return Response({'message':message}, status=status.HTTP_200_OK)
        return Response(serializer_class.errors, status=status.HTTP_400_BAD_REQUEST)

class IdeaFeedbackAPIView(generics.GenericAPIView):
    """
    """
    permission_classes = [IsAuthenticated]
    def get(self, request, *args, **kwargs):
        id = self.kwargs.get('pk', None)
        is_liked = False
        idea = get_object_or_404(Ideas, id=id)
        if idea.likes.filter(id=request.user.id).exists():
            idea.likes.remove(request.user)
            is_liked = False
        else:
            idea.likes.add(request.user)
            is_liked = True
        data = {"total_likes": idea.likes.count(), "is_liked":is_liked}
        message = custom_messages.get("user_feedback")
        return Response({"data":data, "message":message}, status=status.HTTP_200_OK) 

