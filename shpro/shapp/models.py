from django.db import models
from datetime import datetime
from django.contrib.auth.models import User
from django.db.models.signals import post_save

# Create your models here.
from django.urls import reverse


class books(models.Model):
    book_name = models.CharField(max_length=200)
    book_author = models.CharField(max_length=200)
    book_description = models.TextField(max_length=5000)
    book_image1 = models.ImageField(upload_to='book_images')
    book_image2 = models.ImageField(upload_to='book_images', blank=True, null=True)
    book_image3 = models.ImageField(upload_to='book_images', blank=True, null=True)
    book_image4 = models.ImageField(upload_to='book_images', blank=True, null=True)
    book_image5 = models.ImageField(upload_to='book_images', blank=True, null=True)
    book_price = models.IntegerField()
    is_rent = models.BooleanField(default=False)
    rent_days = models.CharField(max_length=100, blank=True, null=True)
    book_list_date = models.DateTimeField(default=datetime.now, blank=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE)

    def get_absolute_url(self):
        return reverse('user_posts')

    def __str__(self):
        return self.book_name


class Cart(models.Model):
    customer = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True)
    total = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "Cart: " + str(self.id)


class CartProduct(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE)
    product = models.ForeignKey(books, on_delete=models.CASCADE)
    rate = models.PositiveIntegerField()
    quantity = models.PositiveIntegerField()
    subtotal = models.PositiveIntegerField()

    def __str__(self):
        return "Cart: " + str(self.cart.id) + " CartProduct: " + str(self.id)


class Feedback(models.Model):
    First_Name = models.CharField(max_length=200, null=True)
    Last_Name = models.CharField(max_length=200, null=True)
    email = models.EmailField(max_length=200, blank=True, null=True)
    phone = models.CharField(max_length=100, blank=True, null=True)
    message = models.TextField(blank=True, null=True)
    published_date = models.DateTimeField(default=datetime.now)
    May_we_contact_you = models.BooleanField(default=False)
    May_we_contact_you_with = models.CharField(max_length=200)

    def __str__(self):
        return f'{self.First_Name} {self.Last_Name}'


class Payment(models.Model):
    stripe_charge_id = models.CharField(max_length=50)
    user = models.ForeignKey(User,
                             on_delete=models.SET_NULL, blank=True, null=True)
    amount = models.FloatField()
    created_dates = models.DateTimeField(default=datetime.now())

    def __str__(self):
        return str(self.user)


class Order(models.Model):
    cart = models.OneToOneField(Cart, on_delete=models.CASCADE)
    ordered_by = models.CharField(max_length=200)
    shipping_address = models.CharField(max_length=200)
    mobile = models.CharField(max_length=10)
    email = models.EmailField(null=True, blank=True)
    subtotal = models.PositiveIntegerField()
    total = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=datetime.now())
    payment_completed = models.BooleanField(
        default=False, null=True, blank=True)

    def __str__(self):
        return "Order: " + str(self.id)


class SendMailRent(models.Model):
    user = models.ForeignKey(User,
                             on_delete=models.SET_NULL, blank=True, null=True)
    book_rent_time = models.CharField(max_length=100, blank=True, null=True)
    created_dates = models.DateTimeField(default=datetime.now())
    
    def __str__(self):
        return str(self.user)