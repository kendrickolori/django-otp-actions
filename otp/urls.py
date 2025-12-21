from django.contrib import admin
from django.urls import path
from .views import health, verify

urlpatterns = [
    path("admin/", admin.site.urls),
    path("generate/", health, name="health"),  # Renamed for clarity
    path("verify/", verify, name="verify"),
]
