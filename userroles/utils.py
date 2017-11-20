# http://djangosnippets.org/snippets/1011/
# Note: If we move to Django 1.4, we can use proper test settings instead.

from django.conf import settings
from django.test import TestCase

NO_SETTING = ('!', None)


class TestSettingsManager(object):
    """
    A class which can modify some Django settings temporarily for a
    test and then revert them to their original values later.

    Automatically handles resyncing the DB if INSTALLED_APPS is
    modified.
    """
    def __init__(self):
        self._original_settings = {}

    def set(self, **kwargs):
        for k, v in kwargs.items():
            self._original_settings.setdefault(k, getattr(settings, k,
                                                          NO_SETTING))
            setattr(settings, k, v)

    def revert(self):
        for k, v in self._original_settings.iteritems():
            if v == NO_SETTING:
                delattr(settings, k)
            else:
                setattr(settings, k, v)
        self._original_settings = {}


class SettingsTestCase(TestCase):
    """
    A subclass of the Django TestCase with a settings_manager
    attribute which is an instance of TestSettingsManager.

    Comes with a tearDown() method that calls
    self.settings_manager.revert().
    """
    def __init__(self, *args, **kwargs):
        super(SettingsTestCase, self).__init__(*args, **kwargs)
        self.settings_manager = TestSettingsManager()

    def tearDown(self):
        self.settings_manager.revert()

    def settings(self, **kwargs):
        self.settings_manager.set(**kwargs)
