from django.contrib import admin

# Register your models here.
from .models import Feedback, books, CartProduct, Cart, Payment, SendMailRent


admin.site.register(Feedback)
admin.site.register(books)
admin.site.register(CartProduct)
admin.site.register(Cart)
admin.site.register(Payment)
admin.site.register(SendMailRent)

