
from urllib import request

from django.conf import settings
import jwt
from rest_framework import authentication, exceptions
from django.conf import settings
from .models import User
class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        import pdb;pdb.set_trace()
        auth_data = authentication.get_authorization_header(request).split()
        if not auth_data:
            return None
        prefix, token = auth_data.decode('utf-8').split(' ')
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(email=payload['email'])
            return user, token
        except jwt.DecodeError as identifier:
            raise exceptions.AuthenticationFailed("Your Token is invalid, login")
        except jwt.ExpiredSignatureError as identifier:
            raise exceptions.AuthenticationFailed("Your Token is expired, login")
        # return super().authenticate(request)
        return super(JWTAuthentication, self).authenticate(request)




# from django.contrib.auth.models import User
# from django.contrib.auth.hashers import make_password, check_password
# from django.conf import settings
# class EmailAuthBackend(object):
#     """
#     Email Authentication Backend

#     Allows a user to sign in using an email/password pair rather than
#     a username/password pair.
#     """

#     def authenticate(self, username=None, password=None):
#         """ Authenticate a user based on email address as the user name. """
#         try:
#             user = User.objects.get(email=username)
#             if user.check_password(password):
#                 return user
#         except User.DoesNotExist:
#                 return None

#     def get_user(self, user_id):
#         """ Get a User object from the user_id. """
#         try:
#             return User.objects.get(pk=user_id)
#         except User.DoesNotExist:
#             return None