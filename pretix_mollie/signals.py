import logging
import time
from collections import OrderedDict

from django import forms
from django.dispatch import receiver
from django.urls import resolve, reverse
from django.utils.translation import ugettext_lazy as _
from django_scopes import scopes_disabled

from pretix.base.models import Event_SettingsStore
from pretix.base.signals import (
    logentry_display, periodic_task, register_global_settings,
    register_payment_providers,
)
from pretix.control.signals import nav_organizer
from .forms import MollieKeyValidator
from .utils import refresh_mollie_token

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


@receiver(nav_organizer, dispatch_uid="mollie_nav_organizer")
def nav_organizer(sender, request, organizer, **kwargs):
    if request.user.has_active_staff_session(request.session.session_key):
        url = resolve(request.path_info)
        return [{
            'label': _('Mollie'),
            'url': reverse('plugins:pretix_mollie:organizer.settings', kwargs={
                'organizer': request.organizer.slug
            }),
            'parent': reverse('control:organizer.edit', kwargs={
                'organizer': request.organizer.slug
            }),
            'active': 'organizer.settings' in url.url_name,
        }]
    return []


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
@scopes_disabled()
def refresh_mollie_tokens(sender, **kwargs):
    seen = set()
    for es in Event_SettingsStore.objects.filter(key='payment_mollie_expires'):
        if float(es.object.settings.payment_mollie_expires) - time.time() < 600:
            rt = es.object.settings.payment_mollie_refresh_token
            if rt not in seen:
                refresh_mollie_token(es.object, True)
                seen.add(rt)
