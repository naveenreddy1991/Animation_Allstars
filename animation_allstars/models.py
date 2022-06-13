# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey has `on_delete` set to the desired behavior.
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from os import access
from django.db import models
from django.contrib.auth.models import AbstractUser, AbstractBaseUser, BaseUserManager, UserManager
from rest_framework_simplejwt.tokens import RefreshToken
import os
from django.core.validators import (
    MaxLengthValidator, MaxValueValidator, MinLengthValidator,
    MinValueValidator,
)
# from django.contrib.auth.models import PermissionsMixin

# class IdeaFeedback(models.Model):
#     idea_user = models.ForeignKey('Ideas', models.DO_NOTHING, blank=True, null=True)
#     feedback_user = models.ForeignKey('User', models.DO_NOTHING, blank=True, null=True)
#     comment = models.CharField(max_length=255, blank=True, null=True)
#     like = models.IntegerField(blank=True, null=True)
#     dislike = models.IntegerField(blank=True, null=True)

#     class Meta:
#         # managed = False
#         db_table = 'idea_feedback'


# class Status(models.Model):
#     # id = models.OneToOneField('User', models.DO_NOTHING, db_column='id', primary_key=True)
#     status = models.ForeignKey('User', models.DO_NOTHING, blank=True, null=True)
#     status_type = models.CharField(max_length=255, blank=True, null=True)

#     class Meta:
#         # managed = False
#         db_table = 'status'

class MyCustomUserManager(BaseUserManager):
    def create_user(self, email_id, first_name, last_name, password=None):
        """
        Creates and saves a User with the given email and password.
        """
        if not email_id:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=MyCustomUserManager.normalize_email(email_id),
            first_name=first_name,
            last_name=last_name,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, first_name, last_name=None):
        u = self.create_user(email_id=email, password=password, first_name=first_name, last_name=last_name)
        u.is_superuser = True
        u.is_staff = True
        u.save(using=self._db)
        return u
def productFile(instance, filename):
    return '/'.join( ['animation_allstars', instance.email,filename] )

class User(AbstractUser):
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)
    birth_year = models.IntegerField(blank=True, null=True)
    password = models.CharField(max_length=255, blank=True, null=True)
    email = models.CharField(max_length=255, unique=True, blank=True, null=True)
    created_on = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    updated_on = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    image_url = models.ImageField(upload_to=productFile, max_length=254, blank=True, null=True)
    # status_cd = models.IntegerField(unique=True, blank=True, null=True)
    email_verified = models.IntegerField(blank=True, null=True)
    about_user = models.CharField(max_length=255, blank=True, null=True)

    objects = MyCustomUserManager()
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            "refresh":str(refresh),
            "access":str(refresh.access_token)
        }
    class Meta:
        db_table = 'user'


def ideafile(instance, filename):
    return '/'.join( ['userprofile/{0}_{1}', str(instance.id),filename] )

def user_directory_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/user_<id>/<filename>
    
    return 'user_{0}/{1}'.format(instance.user.id, filename)

class Ideas(models.Model):
    # id = models.ForeignKey('UserIdea', models.DO_NOTHING, db_column='id', primary_key=True)
    user = models.ForeignKey(User, models.DO_NOTHING, blank=True, null=True)
    idea = models.CharField(max_length=255, blank=True, null=True)
    idea_name = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    genre = models.CharField(max_length=255, blank=True, null=True)
    idea_description = models.CharField(max_length=255, blank=True, null=True)
    file_url = models.FileField(upload_to=user_directory_path)
    file_extension = models.CharField(max_length=255, blank=True, null=True)
    likes = models.ManyToManyField(User, related_name='likes', blank=True)
    created_on = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    updated_on = models.DateTimeField(blank=True, null=True, auto_now_add=True)

    class Meta:
        # managed = False    
        db_table = 'ideas'

class Comment(models.Model):
    ''' Main comment model'''
    users =  models.ForeignKey(User, models.DO_NOTHING)
    user_idea = models.ForeignKey(Ideas, models.DO_NOTHING, blank=True, null=True)
    comment = models.TextField(validators=[MinLengthValidator(15)])
    created_on = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    updated_on = models.DateTimeField(blank=True, null=True, auto_now_add=True)

    # def get_total_likes(self):
    #     import pdb;pdb.set_trace()
    #     return self.likes.users.count()

    # def get_total_dis_likes(self):
    #     return self.dis_likes.users.count()

    class Meta:
        # managed = False
        db_table = 'idea_feedback'

# class Like(models.Model):
#     ''' like  comment '''
#     idea = models.ForeignKey(IdeaFeedback, related_name="likes", on_delete=models.CASCADE)
#     users = models.ManyToManyField(User, related_name='like_users')

# #     def __str__(self):
# #         return str(self.idea)

# class DisLike(models.Model):
#     ''' Dislike  comment '''

#     idea = models.OneToOneField(IdeaFeedback, related_name="dis_likes", on_delete=models.CASCADE)
#     users = models.ManyToManyField(User, related_name='requirement_comment_dis_likes')
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)

#     def __str__(self):
#         return str(self.idea)

