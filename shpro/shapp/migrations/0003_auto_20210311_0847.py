# Generated by Django 3.1.7 on 2021-03-11 08:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('shapp', '0002_emails_phone'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Emails',
            new_name='Feedback',
        ),
    ]
