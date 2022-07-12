from django.urls import path
from .views import *

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register' ),
    path('login/', LoginView.as_view(), name='login' ),
    path('user/', UserView.as_view(), name='loggedin_user'),
    path('logout/', LogoutView.as_view(), name='logout')

]
