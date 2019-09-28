"""steganography_social_media URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf.urls import include,url
from account import views as my_views

urlpatterns = [
    path('admin/', admin.site.urls),
    url(r'^account/login/$',my_views.login,name = 'login'),
    url(r'^account/$',my_views.dashboard , name = 'dashboard'),
    url(r'^account/logout/$',my_views.logout,name = 'logout'),
    url(r'^account/registration/$',my_views.registration,name = 'registration'),
    url(r'^account/follow/$',my_views.follow,name = 'follow'),
    url(r'^account/friends/$',my_views.friends,name = 'friends'),

]
