from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from .models import Users,Followers
from django.urls import reverse
import os
import hashlib
import binascii

def dashboard(request):
	return render(request,'account/dashboard.html',{'section':'dashboard'})

def loginuser(request,user):
	try:
		if request.session['user'] is None:
			print("error")
	except:
		request.session['user'] = user
		print(request.session['user'])
	return request
def login(request):
	def get_value(field_name):
		return request.POST.get(field_name)
	if request.method=='POST':
		username = get_value('username')
		password = get_value('password')
		user = Users.objects.filter(username=username)
		try:
			user,userp = user[0].username , user[0].password
		except:
			print('here is the problem')
			return render(request,'account/login.html',{'notvalid':True})
		if verify_password(userp,password) :
			request = loginuser(request,user)
			return render(request,'account/dashboard.html',{'section':'dashboard'})
		else:
			return render(request,'account/login.html',{'notvalid':True})
	else:
		return render(request,'account/login.html',{})

def logout(request):
	try:
		del request.session['user']
	except:
		print('error in logout')
	return render(request,'account/login.html',{'loggedout':True})


def my_hash_function(password,*args):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

def registration(request):
	already_registered_usernames = list(map(str,Users.objects.all()))
	def get_value(field_name):
		return request.POST.get(field_name)

	if request.method == 'POST':
		username = get_value('username')
		first_name = get_value('first_name')
		last_name  = get_value('last_name')
		date_of_birth = get_value('date_of_birth')
		job_title  = get_value('job_title')
		department = get_value('department')
		email = get_value('email')
		contact = get_value('contact')
		password = my_hash_function(get_value('password1'),username)
		user = Users(username=username,slug = username,first_name=first_name,last_name=last_name,date_of_birth=date_of_birth,job_title=job_title,department=department,email=email,contact_number=contact,password=password)
		user.save()
		return render(request,'account/login.html',{'registered':True})
	else:
		print("Here")
		return render(request,'account/registration.html',{'already_registered_usernames':already_registered_usernames})



def follow(request):
	if request.method =="POST":
		user1 = request.session['user']
		user2 = request.POST.get("username")
		user1 = Users.objects.filter(username=user1)
		user2 = Users.objects.filter(username=user2)
		follow = Followers(user1 = user1[0] , user2 = user2[0])
		follow.save()
	all_users = [x.username for x in Users.objects.exclude(username=request.session['user'])]
	return render(request,'account/users.html',{'all_users':all_users})

def friends(request):
	user = request.session['user']
	user = Users.objects.filter(username=user)[0]
	friends = Followers.objects.filter(user1 = user)
	list_of_friends = [x.user2 for x in friends]
	return render(request,'account/friends.html',{'list_of_friends':list_of_friends})





