from django.conf.urls import include
from django.conf.urls import url


urlpatterns = [
    url(r'^testapp/', include('testproject.testapp.urls', namespace='testapp'))
]
