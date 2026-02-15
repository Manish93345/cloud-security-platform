from django.urls import path
from .views import scan_view
from .views import history_view

urlpatterns = [
    path('scan/', scan_view),
]

urlpatterns = [
    path('scan/', scan_view),
    path('history/', history_view),
]