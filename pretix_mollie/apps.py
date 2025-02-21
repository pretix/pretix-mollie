from django.apps import AppConfig
from django.utils.translation import gettext_lazy

from . import __version__


class PluginApp(AppConfig):
    name = "pretix_mollie"
    verbose_name = "Mollie"

    class PretixPluginMeta:
        name = gettext_lazy("Mollie")
        author = "Raphael Michel"
        description = gettext_lazy(
            "Accept payments through Mollie, a European payment provider supporting "
            "credit cards as well as many local payment methods such as giropay, "
            "direct debit, iDEAL, wire transfers, and many more."
        )
        picture = "pretix_mollie/logo.svg"
        category = "PAYMENT"
        visible = True
        version = __version__
        featured = True
        compatibility = "pretix>=2025.2.0.dev0"

    def ready(self):
        from . import signals  # NOQA
