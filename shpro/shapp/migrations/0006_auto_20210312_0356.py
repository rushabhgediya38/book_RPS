# Generated by Django 3.1.7 on 2021-03-12 03:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('shapp', '0005_auto_20210312_0356'),
    ]

    operations = [
        migrations.AlterField(
            model_name='books',
            name='rent_days',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]