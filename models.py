# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey has `on_delete` set to the desired behavior.
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


class FileExtensions(models.Model):
    file_extension = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'file_extensions'


class Genres(models.Model):
    genre_name = models.CharField(max_length=255, blank=True, null=True)
    genre_description = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'genres'


class IdeaFeedback(models.Model):
    idea_user = models.ForeignKey('UserIdea', models.DO_NOTHING, blank=True, null=True)
    feedback_user = models.ForeignKey('User', models.DO_NOTHING, blank=True, null=True)
    comment = models.CharField(max_length=255, blank=True, null=True)
    like = models.IntegerField(blank=True, null=True)
    dislike = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'idea_feedback'


class Ideas(models.Model):
    id = models.ForeignKey('UserIdea', models.DO_NOTHING, db_column='id', primary_key=True)
    idea_name = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'ideas'


class Status(models.Model):
    id = models.ForeignKey('User', models.DO_NOTHING, db_column='id', primary_key=True)
    status_type = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'status'


class User(models.Model):
    username = models.CharField(max_length=255, blank=True, null=True)
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)
    birth_year = models.IntegerField(blank=True, null=True)
    password = models.CharField(max_length=255, blank=True, null=True)
    email = models.CharField(max_length=255, blank=True, null=True)
    created_on = models.DateTimeField(blank=True, null=True)
    updated_on = models.DateTimeField(blank=True, null=True)
    image_url = models.CharField(max_length=255, blank=True, null=True)
    status_cd = models.IntegerField(unique=True, blank=True, null=True)
    email_verified = models.IntegerField(blank=True, null=True)
    about_user = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'user'


class UserIdea(models.Model):
    user = models.ForeignKey(User, models.DO_NOTHING, unique=True, blank=True, null=True)
    idea_id = models.IntegerField(unique=True, blank=True, null=True)
    genre = models.ForeignKey(Genres, models.DO_NOTHING, blank=True, null=True)
    idea_description = models.CharField(max_length=255, blank=True, null=True)
    file_url = models.CharField(max_length=255, blank=True, null=True)
    file_extension = models.ForeignKey(FileExtensions, models.DO_NOTHING, blank=True, null=True)
    created_on = models.DateTimeField(blank=True, null=True)
    updated_on = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'user_idea'
