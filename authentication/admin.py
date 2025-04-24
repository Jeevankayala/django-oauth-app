from django.contrib import admin
from .models import GoogleToken, ZoomToken, TeamsToken


# Register your models here.
admin.site.register(GoogleToken)
admin.site.register(ZoomToken)
admin.site.register(TeamsToken)