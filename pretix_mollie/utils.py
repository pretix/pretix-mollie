import hashlib
import logging
import time

import requests
from django.core.cache import cache

from pretix.base.models import Event_SettingsStore
from pretix.base.settings import GlobalSettingsObject
from pretix.helpers.urls import build_absolute_uri

logger = logging.getLogger(__name__)


def refresh_mollie_token(event, disable=True):
    # Rate limit
    rt = event.settings.payment_mollie_refresh_token
    if not rt:
        return False
    h = hashlib.sha1(rt.encode()).hexdigest()
    if cache.get('mollie_refresh_{}'.format(h)):
        return False
    cache.set('mollie_refresh_{}'.format(h), 'started', 30)

    gs = GlobalSettingsObject()
    try:
        resp = requests.post('https://api.mollie.com/oauth2/tokens', auth=(
            gs.settings.payment_mollie_connect_client_id,
            gs.settings.payment_mollie_connect_client_secret
        ), data={
            'grant_type': 'refresh_token',
            'refresh_token': event.settings.payment_mollie_refresh_token,
            'redirect_uri': build_absolute_uri('plugins:pretix_mollie:oauth.return')
        })
    except Exception as e:
        logger.exception('Unable to refresh mollie token')
        if float(event.settings.payment_mollie_expires) > time.time() and not \
                event.settings.payment_mollie_api_key and disable:
            event.settings.payment_mollie__enabled = False
            event.log_action('pretix_mollie.event.disabled', {
                'reason': str(e)
            })
        return False
    else:
        if resp.status_code == 200:
            data = resp.json()
            for ev in Event_SettingsStore.objects.filter(key='payment_mollie_refresh_token', value=rt):
                ev.object.settings.payment_mollie_access_token = data['access_token']
                ev.object.settings.payment_mollie_refresh_token = data['refresh_token']
                ev.object.settings.payment_mollie_expires = time.time() + data['expires_in']
            return True
    return False
