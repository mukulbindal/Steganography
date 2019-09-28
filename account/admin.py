from django.contrib import admin

# Register your models here.
from .models import Users,Followers

class UsersAdmin(admin.ModelAdmin):
	# list_display = ('title','slug','author','publish','status')
	# list_filter = ('status','created','publish','author')
	# date_hierarchy = 'publish'
	# prepopulated_fields = {'slug':('title',)}
	# raw_id_fields = ('author',)
	# ordering = ['status','publish']
	# search_fields = ('title','body')
	prepopulated_fields = {'slug':('username',)}

admin.site.register(Users , UsersAdmin)
admin.site.register(Followers)