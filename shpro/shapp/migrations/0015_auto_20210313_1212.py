# Generated by Django 3.1.7 on 2021-03-13 12:12

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('shapp', '0014_auto_20210313_1117'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='order',
            name='discount',
        ),
        migrations.DeleteModel(
            name='UserProfile',
        ),
    ]
