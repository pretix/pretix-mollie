import logging
from collections import OrderedDict

from django import forms
from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _

from pretix.base.forms import SecretKeySettingsField
from pretix.base.settings import settings_hierarkey
from pretix.base.signals import (
    logentry_display, register_global_settings, register_payment_providers,
)

from .forms import MollieKeyValidator

logger = logging.getLogger(__name__)


@receiver(register_payment_providers, dispatch_uid="payment_mollie")
def register_payment_provider(sender, **kwargs):
    from .payment import (
        MollieSettingsHolder, MollieCC, MollieBancontact, MollieBelfius,
        MollieBanktransfer, MollieBitcoin, MollieEPS,
        MollieGiropay, MollieIdeal, MollieINGHomePay, MollieKBC,
        MolliePaysafecard, MollieSofort, MolliePayPal, MollieApplePay,
        MolliePrzelewy24, MollieIn3, MollieKlarnaPaynow, MollieKlarnaPaylater,
        MollieKlarnaSliceit,
    )

    return [
        MollieSettingsHolder,
        MollieCC,
        MollieBancontact,
        MollieBanktransfer,
        MollieBelfius,
        MollieBitcoin,
        MollieEPS,
        MollieGiropay,
        MollieIdeal,
        MollieINGHomePay,
        MollieKBC,
        MolliePaysafecard,
        MollieSofort,
        MolliePayPal,
        MollieApplePay,
        MolliePrzelewy24,
        MollieKlarnaPaynow,
        MollieKlarnaPaylater,
        MollieKlarnaSliceit,
        MollieIn3,
    ]


@receiver(signal=logentry_display, dispatch_uid="mollie_logentry_display")
def pretixcontrol_logentry_display(sender, logentry, **kwargs):
    if not logentry.action_type.startswith('pretix_mollie.event'):
        return

    plains = {
        'canceled': _('Payment canceled.'),
        'failed': _('Payment failed.'),
        'paid': _('Payment succeeded.'),
        'expired': _('Payment expired.'),
        'disabled': _('Payment method disabled since we were unable to refresh the access token. Please '
                      'contact support.'),  # for historical reasons, no longer occurs
    }
    text = plains.get(logentry.action_type[20:], None)
    if text:
        return _('Mollie reported an event: {}').format(text)


settings_hierarkey.add_default('payment_mollie_method_cc', True, bool)
settings_hierarkey.add_default('payment_mollie_product_type', 'digital', str)


@receiver(register_global_settings, dispatch_uid='mollie_global_settings')
def register_global_settings(sender, **kwargs):
    return OrderedDict([
        ('payment_mollie_connect_client_id', forms.CharField(
            label=_('Mollie Connect: Client ID'),
            required=False,
            validators=(
                MollieKeyValidator('app_'),
            ),
        )),
        ('payment_mollie_connect_client_secret', SecretKeySettingsField(
            label=_('Mollie Connect: Client secret'),
            required=False,
        )),
    ])
