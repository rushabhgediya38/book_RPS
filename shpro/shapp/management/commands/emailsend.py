from django.core.management.base import BaseCommand, CommandError
from datetime import datetime, timedelta
from shapp.models import SendMailRent
import time
import schedule
from django.core.mail import send_mail
from django.conf import settings


class Command(BaseCommand):
    def handle(*args, **kwargs):
        rent_days1 = 10
        rent_days2 = 15
        rent_days3 = 20

        if SendMailRent.objects.filter(book_rent_time__exact=rent_days1):
            TB = SendMailRent.objects.filter(
                created_dates__lte=datetime.now() - timedelta(minutes=1), book_rent_time__exact=rent_days1).first()
            if TB:
                print(TB)
                send_mail(
                    'Expired books - wisdom',
                    'You have only 2 days left for expired your rent days',
                    settings.EMAIL_HOST_USER,
                    [TB],
                    fail_silently=False
                )
                TB.delete()
            else:
                print('Email Not Detected')

        elif SendMailRent.objects.filter(book_rent_time__exact=rent_days2):
            TBB = SendMailRent.objects.filter(
                created_dates__lte=datetime.now() - timedelta(minutes=2), book_rent_time__exact=rent_days2).first()
            print(TBB)
            if TBB:
                print(TBB)
                send_mail(
                    'Expired books - wisdom',
                    'You have only 2 days left for expired your rent days',
                    settings.EMAIL_HOST_USER,
                    [TBB],
                    fail_silently=False
                )
                TBB.delete()
            else:
                print('Email Not Detected')

        
        elif SendMailRent.objects.filter(book_rent_time__exact=rent_days3):
            TBB = SendMailRent.objects.filter(
                created_dates__lte=datetime.now() - timedelta(minutes=3), book_rent_time__exact=rent_days3).first()
            if TBB:
                print(TBB)
                send_mail(
                    'Expired books - wisdom',
                    'You have only 2 days left for expired your rent days',
                    settings.EMAIL_HOST_USER,
                    [TBB],
                    fail_silently=False
                )
                TBB.delete()

        else:
            print('Email Not Detected')

    schedule.every(1).seconds.do(handle)


while True:
    schedule.run_pending()
    time.sleep(1)






# elif SendMailRent.objects.filter(book_rent_time__exact=rent_days3):
        #     TBBB = SendMailRent.objects.filter(created_dates__lte=datetime.now() - timedelta(minutes=5))

        #     if TBBB:
        #         send_mail(
        #             'Expired books - wisdom',
        #             'You have only 2 days left for expired your rent days',
        #             settings.EMAIL_HOST_USER,
        #             [TBBB],
        #             fail_silently=False
        #         )
        #         SendMailRent.objects.filter(created_dates__lte=datetime.now() - timedelta(minutes=5)).delete()
        #         print('Email hase been sent 5')
        #     else:
        #         print('TBB is False 5')