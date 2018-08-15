import logging
import time
from collections import OrderedDict

import requests
from django import forms
from django.dispatch import receiver
from django.utils.translation import ugettext_lazy as _
from pretix.base.models import Event_SettingsStore
from pretix.base.settings import GlobalSettingsObject, settings_hierarkey
from pretix.base.signals import (
    logentry_display, periodic_task, register_global_settings,
    register_payment_providers,
)
from pretix.helpers.urls import build_absolute_uri

from .forms import MollieKeyValidator

logger = logging.getLogger(__name__)


@receiver(register_payment_providers, dispatch_uid="payment_mollie")
def register_payment_provider(sender, **kwargs):
    from .payment import (
        MollieSettingsHolder, MollieCC, MollieBancontact, MollieBelfius,
        MollieBanktransfer, MollieBitcoin, MollieEPS,
        MollieGiropay, MollieIdeal, MollieINGHomePay, MollieKBC,
        MolliePaysafecard, MollieSofort
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
        MollieSofort
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
                      'contact support.'),
    }
    text = plains.get(logentry.action_type[20:], None)
    if text:
        return _('Mollie reported an event: {}').format(text)


settings_hierarkey.add_default('payment_mollie_method_cc', True, bool)


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
        ('payment_mollie_connect_client_secret', forms.CharField(
            label=_('Mollie Connect: Client secret'),
            required=False,
        )),
    ])


@receiver(periodic_task, dispatch_uid='mollie_refresh_tokens')
def refresh_mollie_tokens(sender, **kwargs):
    seen = set()
    gs = GlobalSettingsObject()
    for es in Event_SettingsStore.objects.filter(key='payment_mollie_expires'):
        if time.time() - float(es.object.settings.payment_mollie_expires) < 600:
            rt = es.object.settings.payment_mollie_refresh_token
            if rt not in seen:
                try:
                    resp = requests.post('https://api.mollie.com/oauth2/tokens', auth=(
                        gs.settings.payment_mollie_connect_client_id,
                        gs.settings.payment_mollie_connect_client_secret
                    ), data={
                        'grant_type': 'refresh_token',
                        'refresh_token': es.object.settings.payment_mollie_refresh_token,
                        'redirect_uri': build_absolute_uri('plugins:pretix_mollie:oauth.return')
                    })
                except:
                    logger.exception('Unable to refresh mollie token')
                    if float(es.object.settings.payment_mollie_expires) > time.time() and not \
                            es.object.settings.payment_mollie_api_key:
                        es.object.settings.payment_mollie__enabled = False
                        es.object.log_action('pretix_mollie.event.disabled')
                else:
                    if resp.status_code == 200:
                        data = resp.json()
                        for ev in Event_SettingsStore.objects.filter(key='payment_mollie_refresh_token', value=rt):
                            ev.object.settings.payment_mollie_access_token = data['access_token']
                            ev.object.settings.payment_mollie_refresh_token = data['refresh_token']
                            ev.object.settings.payment_mollie_expires = time.time() + data['expires_in']
                        seen.add(rt)
