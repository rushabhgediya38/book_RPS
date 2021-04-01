# Generated by Django 3.1.7 on 2021-03-28 12:54

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('shapp', '0018_auto_20210328_1237'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='payment',
            name='book_rent_time',
        ),
        migrations.AlterField(
            model_name='payment',
            name='created_dates',
            field=models.DateTimeField(default=datetime.datetime(2021, 3, 28, 18, 24, 48, 296676)),
        ),
        migrations.CreateModel(
            name='SendMailRent',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('book_rent_time', models.CharField(blank=True, max_length=100, null=True)),
                ('created_dates', models.DateTimeField(default=datetime.datetime(2021, 3, 28, 18, 24, 48, 297981))),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]