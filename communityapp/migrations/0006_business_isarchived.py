# Generated by Django 5.1 on 2024-09-11 18:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('communityapp', '0005_review_isarchived'),
    ]

    operations = [
        migrations.AddField(
            model_name='business',
            name='isArchived',
            field=models.BooleanField(default=False),
        ),
    ]
