from django.conf.urls import url

from testproject.testapp import views

urlpatterns = [
    url(r'^manager_or_moderator/$',
        views.manager_or_moderator,
        name='manager_or_moderator')
]
