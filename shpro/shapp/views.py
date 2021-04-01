from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.views.generic import ListView, UpdateView, DeleteView, TemplateView, View, CreateView
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.html import strip_tags
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from validate_email import validate_email
import threading
from .forms import CheckoutForm
from .models import Feedback, books, Cart, CartProduct, Payment, Order, SendMailRent
from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages, auth
from django.conf import settings

import json
import requests
import stripe
from django.urls import reverse_lazy, reverse
from django.utils.decorators import method_decorator

stripe.api_key = settings.STRIPE_SECRET_KEY

from datetime import datetime


# models

# threading

# This is for validate email (install like this pip install validate-email/ and also check check_regex=True,
# check_mx=True for if user enter not valid gmail account than throw the error)

# sending email

# reset password start here

# this is for online email verification


class EmailThread(threading.Thread):

    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()


class EcomMixin(object):
    def dispatch(self, request, *args, **kwargs):
        cart_id = request.session.get("cart_id")
        if cart_id:
            cart_obj = Cart.objects.get(id=cart_id)
            if request.user.is_authenticated and request.user:
                cart_obj.customer = request.user
                cart_obj.save()
        return super().dispatch(request, *args, **kwargs)


@method_decorator(login_required, name='dispatch')
class AddToCartView(EcomMixin, TemplateView):
    template_name = "addtocart.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # get product id from requested url
        product_id = self.kwargs['pro_id']
        # get product
        product_obj = books.objects.get(id=product_id)

        # print(product_id, product_obj)

        # check if cart exists
        cart_id = self.request.session.get("cart_id", None)
        if cart_id:
            cart_obj = Cart.objects.get(id=cart_id)
            this_product_in_cart = cart_obj.cartproduct_set.filter(
                product=product_obj)
            # print(this_product_in_cart)

            # item already exists in cart
            if this_product_in_cart.exists():
                cartproduct = this_product_in_cart.last()
                cartproduct.quantity += 1
                cartproduct.subtotal += product_obj.book_price
                cartproduct.save()
                cart_obj.total += product_obj.book_price
                cart_obj.save()

            # new item is added in cart
            else:
                cartproduct = CartProduct.objects.create(
                    cart=cart_obj, product=product_obj, rate=product_obj.book_price, quantity=1,
                    subtotal=product_obj.book_price)
                cart_obj.total += product_obj.book_price
                cart_obj.save()

        # check if cart does not exists
        else:
            cart_obj = Cart.objects.create(total=0)
            self.request.session['cart_id'] = cart_obj.id
            cartproduct = CartProduct.objects.create(
                cart=cart_obj, product=product_obj, rate=product_obj.book_price, quantity=1,
                subtotal=product_obj.book_price)
            cart_obj.total += product_obj.book_price
            cart_obj.save()

        return context


@method_decorator(login_required, name='dispatch')
class MyCartView(EcomMixin, TemplateView):
    template_name = "mycart.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        cart_id = self.request.session.get("cart_id", None)
        if cart_id:
            cart = Cart.objects.get(id=cart_id)
        else:
            cart = None
        context['cart'] = cart
        return context


@method_decorator(login_required, name='dispatch')
class ManageCartView(EcomMixin, View):
    def get(self, request, *args, **kwargs):
        cp_id = self.kwargs["cp_id"]
        action = request.GET.get("action")
        # print(action)
        cp_obj = CartProduct.objects.get(id=cp_id)
        cart_obj = cp_obj.cart

        if action == "inc":
            cp_obj.quantity += 1
            cp_obj.subtotal += cp_obj.rate
            cp_obj.save()
            cart_obj.total += cp_obj.rate
            cart_obj.save()
        elif action == "dcr":
            cp_obj.quantity -= 1
            cp_obj.subtotal -= cp_obj.rate
            cp_obj.save()
            cart_obj.total -= cp_obj.rate
            cart_obj.save()
            if cp_obj.quantity == 0:
                cp_obj.delete()

        elif action == "rmv":
            cart_obj.total -= cp_obj.subtotal
            cart_obj.save()
            cp_obj.delete()
        else:
            pass
        return redirect("mycart")


@method_decorator(login_required, name='dispatch')
class EmptyCartView(EcomMixin, View):
    def get(self, request, *args, **kwargs):
        cart_id = request.session.get("cart_id", None)
        if cart_id:
            cart = Cart.objects.get(id=cart_id)
            cart.cartproduct_set.all().delete()
            cart.total = 0
            cart.save()
        return redirect("mycart")


# class CheckoutView(EcomMixin, CreateView):
#     template_name = "checkout.html"
#     form_class = CheckoutForm
#     success_url = reverse_lazy("wisdom_page")
#
#     def dispatch(self, request, *args, **kwargs):
#         if request.user.is_authenticated and request.user:
#             pass
#         else:
#             return render(request, 'index.html')
#         return super().dispatch(request, *args, **kwargs)
#
#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         cart_id = self.request.session.get("cart_id", None)
#         if cart_id:
#             cart_obj = Cart.objects.get(id=cart_id)
#         else:
#             cart_obj = None
#         context['cart'] = cart_obj
#         return context
#
#     def form_valid(self, form):
#         cart_id = self.request.session.get("cart_id")
#         if cart_id:
#             cart_obj = Cart.objects.get(id=cart_id)
#             form.instance.cart = cart_obj
#             form.instance.subtotal = cart_obj.total
#             form.instance.total = cart_obj.total
#             del self.request.session['cart_id']
#             order = form.save()
#
#         else:
#             return redirect("wisdom_page")
#         return super().form_valid(form)

class CheckoutView(EcomMixin, LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        cart_id = self.request.session.get("cart_id", None)
        u_Form = CheckoutForm()
        if cart_id:
            cart_obj = Cart.objects.get(id=cart_id)
        else:
            cart_obj = None

        context = {
            'cart': cart_obj,
            'form': u_Form
        }
        return render(request, 'checkout.html', context)

    def post(self, request, *args, **kwargs):
        cart_id = self.request.session.get("cart_id")
        cart_obj = Cart.objects.get(id=cart_id)

        order = Order.objects.all()
        
        book_name = self.request.POST.get('bookName')
        Books_Days = self.request.POST.get('BooksDays')
        print(book_name, Books_Days)
        order_by1 = self.request.POST.get('ordered_by')
        shipping_address1 = self.request.POST.get('shipping_address')
        mobile1 = self.request.POST.get('mobile')
        email1 = self.request.POST.get('email')
        token = self.request.POST.get('stripeToken')

        user_email = self.request.user.email
        # print(user_email)

        # print(token)
        amount1 = int(cart_obj.total)
        # print(amount1)
        try:
            customer = stripe.Customer.create(
                email=email1,
                name=order_by1,
                source=token,
                address={
                    'line1': 'adres_users',
                    'postal_code': '56259',
                    'city': 'Mumbai',
                    'state': 'Mumbai',
                    'country': 'INDIA',
                },

            )

            charge = stripe.Charge.create(
                customer=customer,
                amount=amount1,
                currency='inr',
                description="classifieds Ads"

            )

            now_d = datetime.now()

            # create payment
            payments = Payment()
            payments.stripe_charge_id = charge['id']
            payments.user = self.request.user
            payments.amount = amount1
            payments.save()

            rb = SendMailRent()
            rb.user = self.request.user
            rb.book_rent_time = Books_Days
            rb.save()

            # assign payment to the order
            for ob in order:
                ob.cart = cart_obj
                ob.ordered_by = order_by1
                ob.shipping_address = shipping_address1
                ob.mobile = mobile1
                ob.email = email1
                ob.subtotal = amount1
                ob.total = amount1
                ob.payment_completed = True
                ob.save()
            
            
            # email_subject = 'Thank you buying books - wisdom'
            # message = render_to_string('thankyou.html')

            # message_content = strip_tags(message)

            # email_message = EmailMultiAlternatives(
            #     email_subject,
            #     message_content,
            #     settings.EMAIL_HOST_USER,
            #     [user_email],
            # )

            # email_message.attach_alternative(message, "text/html")
            # EmailThread(email_message).start()
            
            del self.request.session['cart_id']
            messages.success(self.request, 'payment successful')
            return redirect('/')

        except stripe.error.CardError as e:
            body = e.json_body
            err = body.get('error', {})
            messages.warning(self.request, f"{err.get('message')}")
            return redirect("/")

        except stripe.error.RateLimitError as e:
            # Too many requests made to the API too quickly
            messages.warning(self.request, "Rate limit error")
            return redirect("/")

        except stripe.error.InvalidRequestError as e:
            # Invalid parameters were supplied to Stripe's API
            print(e)
            messages.warning(self.request, "Invalid parameters")
            return redirect("/")

        except stripe.error.AuthenticationError as e:
            # Authentication with Stripe's API failed
            # (maybe you changed API keys recently)
            messages.warning(self.request, "Not authenticated")
            return redirect("/")

        except stripe.error.APIConnectionError as e:
            # Network communication with Stripe failed
            messages.warning(self.request, "Network error")
            return redirect("/")

        except stripe.error.StripeError as e:
            # Display a very generic error to the user, and maybe send
            # yourself an email
            messages.warning(
                self.request, "Something went wrong. You were not charged. Please try again.")
            return redirect("/")

        except Exception as e:
            # send an email to ourselves
            messages.warning(
                self.request, "A serious error occurred. We have been notified.")
            return redirect("/")


class PostDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = books
    success_url = '/'

    def test_func(self):
        post = self.get_object()
        if self.request.user == post.author:
            return True
        return False


class PostUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = books
    context_object_name = 'form'
    template_name = 'books_update.html'
    fields = [
        'book_name',
        'book_author',
        'book_description',
        'book_image1',
        'book_image2',
        'book_image3',
        'book_image4',
        'book_image5',
        'book_price',
        'is_rent',
        'rent_days',
    ]

    def form_valid(self, form):
        form.instance.author = self.request.user
        return super().form_valid(form)

    def test_func(self):
        post = self.get_object()
        if self.request.user == post.author:
            return True
        return False


class UserPostListView(LoginRequiredMixin, ListView):
    model = books
    template_name = 'user_books.html'  # <app>/<model>_<viewtype>.html
    context_object_name = 'qs'

    def get_queryset(self):
        user = get_object_or_404(User, username=self.request.user)
        print(user)
        return books.objects.filter(author=user)


def autocompleteModel(request):
    if request.method == 'POST':
        se = request.POST['txtSearch']

        v = books.objects.filter(book_name__icontains=se)

        context = {
            'v': v
        }

        if v:
            return render(request, 'search.html', context)
        else:
            return HttpResponse('book not available')


def index(request):
    news_api = requests.get("https://newsapi.org/v2/top-headlines?sources=google-news-in&apiKey"
                            "=3ad9b008ef0d4d5f813cc71c76842d5f")

    api = json.loads(news_api.content)

    context = {
        'api': api
    }

    return render(request, 'index.html', context)


def about_us(request):
    return render(request, 'aboutus.html')


def contact_us(request):
    return render(request, 'contactus.html')


@login_required()
def book_details(request, id):
    qs = books.objects.all().filter(pk=id)

    context = {
        'qs': qs
    }

    return render(request, 'book_details.html', context)


@login_required()
def wisdom_page(request):
    qs = books.objects.filter(is_rent=False)
    qs1 = books.objects.filter(is_rent=True)

    context = {
        'qs': qs,
        'qs1': qs1
    }
    return render(request, 'welcome.html', context)


@login_required()
def book_lists(request):
    qs = books.objects.filter(is_rent=False)
    context = {
        'qs': qs,
    }
    return render(request, 'book_lists.html', context)


@login_required()
def rent_lists(request):
    qs = books.objects.filter(is_rent=True)
    context = {
        'qs': qs,
    }
    return render(request, 'rent_lists.html', context)


@login_required()
def book_post(request):
    if request.method == 'POST' or request.FILES:
        user1 = request.user
        name = request.POST['book_name']
        author = request.POST['book_author']
        description = request.POST['book_description']
        image1 = request.FILES.get('book_picture1')
        image2 = request.FILES.get('book_picture2', None)
        image3 = request.FILES.get('book_picture3', None)
        image4 = request.FILES.get('book_picture4', None)
        image5 = request.FILES.get('book_picture5', None)
        price = request.POST['book_price']
        isrent = request.POST.get('is_rent_book')
        rentdays = request.POST['book_days']
        print(rentdays)

        if isrent == "on":
            isrent = True
        else:
            isrent = False

        final_post = books.objects.create(author=user1, book_name=name,
                                          book_author=author,
                                          book_description=description,
                                          book_image1=image1,
                                          book_image2=image2,
                                          book_image3=image3,
                                          book_image4=image4,
                                          book_image5=image5,
                                          book_price=price,
                                          is_rent=isrent,
                                          rent_days=rentdays)
        final_post.save()
        return redirect('book_lists')

    return render(request, 'SellRent.html')


# login start

def login(request):
    if request.method == 'POST':
        username1 = request.POST['username5']
        password1 = request.POST['password3']

        context = {
            'has_error': False
        }

        if username1 == '':
            messages.add_message(request, messages.ERROR, 'Email is required')
            context['has_error']: True

        if password1 == '':
            messages.add_message(request, messages.ERROR,
                                 'Password is required')
            context['has_error']: True

        user = auth.authenticate(username=username1, password=password1)
        print(user)
        if user is not None:
            auth.login(request, user)
            return redirect('wisdom_page')
        else:
            messages.add_message(request, messages.ERROR,
                                 'Please enter valid email address')
            return render(request, 'index.html', status=401, context=context)

    else:
        return render(request, 'index.html')


def signup(request):
    if request.method == 'POST':
        email1 = request.POST['email']
        email = email1.lower()
        password = request.POST['password']
        password1 = request.POST['password1']

        context = {
            'has_error': False
        }

        if email == '':
            messages.add_message(request, messages.ERROR, 'Email is required')
            context['has_error']: True

        if password == '':
            messages.add_message(request, messages.ERROR,
                                 'Password is required')
            context['has_error']: True

        if password1 == '':
            messages.add_message(request, messages.ERROR,
                                 'Confirm Password is required')
            context['has_error']: True

        # validate email or not
        if not validate_email(email):
            messages.add_message(request, messages.ERROR,
                                 'please provide a valid Email')
            context['has_error'] = True

        # Email Already exists or not if yes than show this error
        if User.objects.filter(username=email).exists():
            messages.add_message(request, messages.ERROR,
                                 'Email Already Exists')
            context['has_error'] = True

        # password should match
        if password != password1:
            messages.add_message(request, messages.ERROR, 'Password Not Match')
            context['has_error'] = True

        if len(password) < 7:
            messages.add_message(request, messages.ERROR,
                                 'password shod be Atleast 7 character or more')
            context['has_error'] = True

        if context['has_error']:
            return redirect('/')
            # return render(request, 'index.html', context, status=400)
        messages.success(request, "user created successfullyy!")
        user = User.objects.create_user(username=email, password=password1)
        user.save()
        return redirect('/')

    else:
        return render(request, 'index.html')


@login_required()
def logout(request):
    if request.method == 'GET':
        auth.logout(request)
        messages.success(request, "logout successful")
        return render(request, 'index.html')


def ResetPassword(request):
    context = {
        'has_error': False
    }

    if request.method == 'POST':
        email = request.POST['email']

        user_email_check = User.objects.filter(email=email)

        if email == '':
            messages.add_message(request, messages.ERROR, 'Email is required')
            context['has_error']: True

        if user_email_check:
            pass
        else:
            messages.add_message(request, messages.ERROR,
                                 'Email is not registered')
            context['has_error']: True

        user = User.objects.filter(email=email)

        if user.exists():
            current_site = get_current_site(request)
            email_subject = 'Password Reset Request for book'
            message = render_to_string('userall/ResetPasswordEmailForm.html',
                                       {
                                           'domain': current_site.domain,
                                           'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                                           'token': PasswordResetTokenGenerator().make_token(user[0]),

                                       }
                                       )
            message_content = strip_tags(message)

            email_message = EmailMultiAlternatives(
                email_subject,
                message_content,
                settings.EMAIL_HOST_USER,
                [email],
            )

            email_message.attach_alternative(message, "text/html")

            EmailThread(email_message).start()

            messages.success(
                request, 'We have sent you email with instruction on how to reset password')
            return render(request, 'userall/ForgetPassword.html')

    return render(request, 'userall/ForgetPassword.html', context)


def Setnewpassword(request, uidb64, token):
    if request.method == 'GET':
        context = {
            'uidb64': uidb64,
            'token': token
        }
        return render(request, 'userall/set-new-password.html', context)

    if request.method == 'POST':
        context = {
            'uidb64': uidb64,
            'token': token,
            'has_error': False
        }

        password = request.POST['password']
        password1 = request.POST['password1']

        if password == '':
            messages.add_message(request, messages.ERROR,
                                 'Password is required')
            context['has_error']: True

        if password1 == '':
            messages.add_message(request, messages.ERROR,
                                 'Confirm Password is required')
            context['has_error']: True

        if password != password1:
            messages.add_message(request, messages.ERROR, 'Password Not Match')
            context['has_error'] = True

        if len(password) < 7:
            messages.add_message(request, messages.ERROR,
                                 'password shod be Atleast 7 character or more')
            context['has_error'] = True

        if context['has_error']:
            return render(request, 'userall/set-new-password.html', context)

        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))

            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()

            messages.success(
                request, 'password reset success, you can login with new password')
            return redirect('login')

        except DjangoUnicodeDecodeError as identifier:
            messages.error(request, 'Something went wrong')
            return render(request, 'userall/set-new-password.html', context)

    return render(request, 'userall/set-new-password.html')


@login_required()
def del_user(request):
    user1 = request.user.username
    try:
        u = User.objects.get(username=user1)
        u.delete()
        messages.success(request, "The user is deleted")

    except User.DoesNotExist:
        messages.error(request, "User doesnot exist")
        return render(request, '/')

    return redirect('/')


def Feedback_user(request):
    if request.method == 'POST':
        F_name = request.POST['firstname']
        L_name = request.POST['lastname']
        TelPhone = request.POST['telnum']
        contact_you = request.POST.get('approve')
        select1 = request.POST.get('select1')
        email = request.POST['email']
        message = request.POST['feedback']

        if contact_you == "on":
            contact_you = True
        else:
            contact_you = False

        contact = Feedback(First_Name=F_name, Last_Name=L_name, email=email, phone=TelPhone,
                           May_we_contact_you=contact_you,
                           May_we_contact_you_with=select1, message=message)
        contact.save()

        # send mail

        send_mail(
            'Your Ad Inquiry',
            'There has been an Feedback ' + ' Message From: ' + email + ' Message: ' + message,
            email,
            [settings.EMAIL_HOST_USER],  # user send email to your email
            fail_silently=False
        )

        messages.success(request, 'mail has been send.')
        return redirect('index')

# https://gitlab.com/ecedreamer/ecomtuts/-/blob/master/ecomapp/views.py
# https://github.com/justdjango/django-ecommerce/blob/260952e75344a88a2b4af56a357ec457fa354542/core/views.py#L32


# steps: 1 pip install -r requirements.txt 2 python manage.py collectstatic 3 go to settings file 4 update your
# database 5 put your email and password 6 go to goolge and search
# https://myaccount.google.com/lesssecureapps?pli=1&rapt=AEjHL4M5RY1DtFfN9oGaVb4-37XjsAZU3AQaJ-jrsyETEwPOye1O0bjAWI
# -SLbtPiKtWS-0fBn2csmpw68yXkZp84L5PrS_ORw 7 turn on 8 put your stipe PUBLIC_KEY 9 put your stipe SECRET_KEY 10
# python manage.py makemigrations 11 python manage.py migrate
