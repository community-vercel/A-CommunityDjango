# Generated by Django 5.1 on 2024-09-11 17:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('communityapp', '0004_review_email'),
    ]

    operations = [
        migrations.AddField(
            model_name='review',
            name='isArchived',
            field=models.BooleanField(default=False),
        ),
    ]
