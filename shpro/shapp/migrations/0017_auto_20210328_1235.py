# Generated by Django 3.1.7 on 2021-03-28 12:35

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('shapp', '0016_payment_book_rent_time'),
    ]

    operations = [
        migrations.RenameField(
            model_name='payment',
            old_name='timestamp',
            new_name='created_dates',
        ),
    ]