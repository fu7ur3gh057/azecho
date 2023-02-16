from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

API_URL = 'api/v1'

urlpatterns = [
    path('admin/', admin.site.urls),
    path(f'{API_URL}/auth/', include('apps.users.api.urls')),
]
