# Generated by Django 3.1.7 on 2021-03-12 03:55

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('shapp', '0003_auto_20210311_0847'),
    ]

    operations = [
        migrations.CreateModel(
            name='books',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('book_name', models.CharField(max_length=200)),
                ('book_author', models.CharField(max_length=200)),
                ('book_description', models.TextField(max_length=5000)),
                ('book_image1', models.ImageField(upload_to='book_images')),
                ('book_image2', models.ImageField(blank=True, null=True, upload_to='book_images')),
                ('book_image3', models.ImageField(blank=True, null=True, upload_to='book_images')),
                ('book_image4', models.ImageField(blank=True, null=True, upload_to='book_images')),
                ('book_image5', models.ImageField(blank=True, null=True, upload_to='book_images')),
                ('book_price', models.IntegerField()),
                ('is_rent', models.BooleanField(default=True)),
                ('rent_days', models.CharField(max_length=100)),
                ('book_list_date', models.DateTimeField(blank=True, default=datetime.datetime.now)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]