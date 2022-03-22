from django.apps import AppConfig
from django.utils.translation import gettext_lazy


class PluginApp(AppConfig):
    name = 'pretix_mollie'
    verbose_name = 'Mollie'

    class PretixPluginMeta:
        name = gettext_lazy('Mollie')
        author = 'Raphael Michel'
        description = gettext_lazy('Accept payments through Mollie, a European payment provider supporting '
                                   'credit cards as well as many local payment methods such as giropay, '
                                   'direct debit, iDEAL, wire transfers, and many more.')
        picture = "pretix_mollie/logo.svg"
        category = 'PAYMENT'
        visible = True
        version = '1.3.2'

    def ready(self):
        from . import signals  # NOQA


default_app_config = 'pretix_mollie.PluginApp'
