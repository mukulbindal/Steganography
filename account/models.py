from django.db import models
from django.utils import timezone
from django.urls import reverse


class Users(models.Model):
	CHOICES_FOR_JOBPOST = (('SE','System Engineer'),('SD','System Designer'))
	username = models.CharField(max_length=200,unique = True)
	slug = models.SlugField(max_length = 200 , unique=True,default= username)
	first_name = models.CharField(max_length = 50)
	last_name = models.CharField(max_length=50,blank = True, null = True)
	date_of_birth = models.DateField(default= timezone.now)
	job_title = models.CharField(max_length = 50 , blank = True, null = True)
	department = models.CharField(max_length = 50,blank=True, null = True)
	password = models.CharField(max_length=50)
	email = models.EmailField(max_length = 100)
	contact_number = models.CharField(max_length = 12, unique = False, blank=True, null = True)
	status_is_active = models.BooleanField(default=True)
	date_of_joining = models.DateTimeField(default = timezone.now)
	class Meta:
		ordering = ('-username',)
	def __str__(self):
		return self.username
	# def get_absolute_url(self):
	# 	return "editthisfield"

class Followers(models.Model):
	user1  = models.ForeignKey(Users,related_name="followes",on_delete=None)
	user2  = models.ForeignKey(Users,related_name="followed",on_delete=None)
	time_when_followed = models.DateTimeField(default=timezone.now)
	class Meta:
		ordering = ('-user1',)
	def __str__(self):
		return self.user1.username + " followes "+self.user2.username


