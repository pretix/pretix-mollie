from django.apps import AppConfig
from django.utils.translation import gettext_lazy


class PluginApp(AppConfig):
    name = 'pretix_mollie'
    verbose_name = 'Mollie payment integration for pretix'

    class PretixPluginMeta:
        name = gettext_lazy('Mollie')
        author = 'Raphael Michel'
        description = gettext_lazy('Integration for the Mollie payment provider.')
        category = 'PAYMENT'
        visible = True
        version = '1.3.2'

    def ready(self):
        from . import signals  # NOQA


default_app_config = 'pretix_mollie.PluginApp'
