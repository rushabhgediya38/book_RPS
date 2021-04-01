from django.urls import path, include
from . import views
from django.contrib import admin


urlpatterns = [
    path('', views.index, name='index'),
    path('user/admin/', admin.site.urls, name="admin"),
    path('about_us/', views.about_us, name="about_us"),
    path('contact_us/', views.contact_us, name="contact_us"),
    path('wisdom_page/', views.wisdom_page, name="wisdom_page"),
    path('book_lists/', views.book_lists, name="book_lists"),
    path('rent_lists/', views.rent_lists, name="rent_lists"),
    path('book_lists/<int:id>/', views.book_details, name="book_details"),
    path('book_post/', views.book_post, name="book_post"),
    path('search/', views.autocompleteModel, name="search"),
    path('profile/user/', views.UserPostListView.as_view(), name='user_posts'),
    path('user/<int:pk>/update/', views.PostUpdateView.as_view(), name='user_book_update'),
    path('user/<int:pk>/delete/', views.PostDeleteView.as_view(template_name='book_confirm_delete.html'),
         name='user_book_delete'),

    # cart functionality
    path('add-to-cart-<int:pro_id>/', views.AddToCartView.as_view(), name="addtocart"),
    path('my-cart/', views.MyCartView.as_view(), name="mycart"),
    path('manage-cart/<int:cp_id>/', views.ManageCartView.as_view(), name="managecart"),
    path('empty-cart/', views.EmptyCartView.as_view(), name="emptycart"),
    path('checkout/', views.CheckoutView.as_view(), name="checkout"),

    path('user/signup/', views.signup, name='signup'),
    path('user/login/', views.login, name='login'),
    path('user/logout/', views.logout, name='logout'),
    path('ResetPassword/', views.ResetPassword, name='ResetPassword'),
    path('set-new-password/<uidb64>/<token>', views.Setnewpassword, name='set-new-password'),
    path('user/delete/', views.del_user, name='account_delete'),
    path('user/Feedback/', views.Feedback_user, name='Feedback_user'),
]
