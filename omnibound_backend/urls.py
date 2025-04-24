from django.contrib import admin
from django.urls import path, include


urlpatterns = [
    path('admin/', admin.site.urls),
    # path('api-auth/', include('rest_framework.urls')),   # remove later
    path('api/', include('authentication.urls')),
    path('api/input-data/', include('input_data_management.urls')),
]