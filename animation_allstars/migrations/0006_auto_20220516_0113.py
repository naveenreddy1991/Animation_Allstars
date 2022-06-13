# Generated by Django 2.2.27 on 2022-05-15 19:43

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('animation_allstars', '0005_auto_20220516_0100'),
    ]

    operations = [
        migrations.AddField(
            model_name='ideas',
            name='likes',
            field=models.ManyToManyField(blank=True, related_name='likes', to=settings.AUTH_USER_MODEL),
        ),
        migrations.DeleteModel(
            name='Like',
        ),
    ]
