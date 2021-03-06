# Generated by Django 2.2.27 on 2022-05-15 19:58

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('animation_allstars', '0006_auto_20220516_0113'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='ideas',
            name='likes',
        ),
        migrations.CreateModel(
            name='Like',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('idea', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='likes', to='animation_allstars.IdeaFeedback')),
                ('users', models.ManyToManyField(related_name='like_users', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
