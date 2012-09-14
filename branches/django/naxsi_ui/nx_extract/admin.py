from django.contrib import admin
from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import User, Group
from django.contrib.sites.models import Site
from django.contrib.auth.admin import UserAdmin as AuthUserAdmin
from nx_extract.models import nx_fmt,nx_user


class UserProfileInline(admin.StackedInline):
    model = nx_user
    max_num = 1
    can_delete = False

class UserAdmin(AuthUserAdmin):
    inlines = [UserProfileInline]

admin.site.unregister(User)
admin.site.unregister(Group)
admin.site.unregister(Site)



admin.site.register(User, UserAdmin)
admin.site.register(nx_fmt)
