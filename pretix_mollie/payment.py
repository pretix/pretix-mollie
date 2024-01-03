import hashlib
import json
import logging
import textwrap
from collections import OrderedDict
from decimal import Decimal
from datetime import timedelta

import pytz
import requests
from django import forms
from django.core import signing
from django.db import transaction
from django.forms.widgets import TextInput
from django.http import HttpRequest
from django.template.loader import get_template
from django.urls import reverse
from django.utils.crypto import get_random_string
from urllib.parse import quote

from django.utils.html import format_html
from django.utils.timezone import now
from django.utils.translation import pgettext, gettext_lazy as _
from i18nfield.strings import LazyI18nString

from pretix.base.reldate import RelativeDateField, RelativeDateWrapper, RelativeDateWidget, BASE_CHOICES
from pretix.helpers import OF_SELF
from pretix_mollie.utils import refresh_mollie_token
from requests import HTTPError

from pretix.base.models import Event, OrderPayment, OrderRefund, Order, InvoiceAddress, OrderFee
from pretix.base.payment import BasePaymentProvider, PaymentException
from pretix.base.settings import SettingsSandbox
from pretix.helpers.urls import build_absolute_uri as build_global_uri
from pretix.multidomain.urlreverse import build_absolute_uri
from pretix.presale.views.cart import cart_session
from .forms import MollieKeyValidator

logger = logging.getLogger(__name__)


class SecretKeyInput(TextInput):

    def __init__(self, secret_key, attrs=None):
        self.secret_key = secret_key
        if attrs is None:
            attrs = {}
        attrs.update({
            'placeholder': self.secret_key[:5] + "*" * len(self.secret_key[5:]),
            'autocomplete': 'new-password'  # see https://bugs.chromium.org/p/chromium/issues/detail?id=370363#c7
        })
        super().__init__(attrs)

    def get_context(self, name, value, attrs):
        value = None
        return super().get_context(name, value, attrs)


class MollieSettingsHolder(BasePaymentProvider):
    identifier = 'mollie'
    verbose_name = _('Mollie')
    is_enabled = False
    is_meta = True

    def __init__(self, event: Event):
        super().__init__(event)
        self.settings = SettingsSandbox('payment', 'mollie', event)

    def get_connect_url(self, request):
        request.session['payment_mollie_oauth_event'] = request.event.pk
        if 'payment_mollie_oauth_token' not in request.session:
            request.session['payment_mollie_oauth_token'] = get_random_string(32)
        return (
            "https://www.mollie.com/oauth2/authorize?client_id={}&redirect_uri={}"
            "&state={}&scope=payments.read+payments.write+refunds.read+refunds.write+profiles.read+organizations.read+orders.read+orders.write"
            "&response_type=code&approval_prompt=auto"
        ).format(
            self.settings.connect_client_id,
            quote(build_global_uri('plugins:pretix_mollie:oauth.return')),
            request.session['payment_mollie_oauth_token'],
        )

    def settings_content_render(self, request):
        if self.settings.connect_client_id and not self.settings.api_key:
            # Use Mollie Connect
            if not self.settings.access_token:
                return (
                    "<p>{}</p>"
                    "<a href='{}' class='btn btn-primary btn-lg'>{}</a>"
                ).format(
                    _('To accept payments via Mollie, you will need an account at Mollie. By clicking on the '
                      'following button, you can either create a new Mollie account connect pretix to an existing '
                      'one.'),
                    self.get_connect_url(request),
                    _('Connect with Mollie')
                )
            else:
                h = ""
                if 'orders.write' not in (self.settings.connect_scope or ''):
                    h += (
                        "<button formaction='{}' class='btn btn-default'>{}</button> "
                    ).format(
                        self.get_connect_url(request),
                        _('Reconnect to Mollie (update permissions)')
                    )

                h += (
                    "<button formaction='{}' class='btn btn-danger'>{}</button>"
                ).format(
                    reverse('plugins:pretix_mollie:oauth.disconnect', kwargs={
                        'organizer': self.event.organizer.slug,
                        'event': self.event.slug,
                    }),
                    _('Disconnect from Mollie')
                )
                return h

    @property
    def test_mode_message(self):
        if self.settings.connect_client_id and not self.settings.api_key:
            is_testmode = True
        else:
            is_testmode = 'test_' in self.settings.secret_key
        if is_testmode:
            return _('The Mollie plugin is operating in test mode. No money will actually be transferred.')
        return None

    @property
    def settings_form_fields(self):
        if self.settings.connect_client_id and not self.settings.api_key:
            # Mollie Connect
            if self.settings.access_token:
                fields = [
                    ('connect_org_name',
                     forms.CharField(
                         label=_('Mollie account'),
                         disabled=True
                     )),
                    ('connect_profile',
                     forms.ChoiceField(
                         label=_('Website profile'),
                         choices=self.settings.get('connect_profiles', as_type=list) or []
                     )),
                    ('endpoint',
                     forms.ChoiceField(
                         label=_('Endpoint'),
                         initial='live',
                         choices=(
                             ('live', pgettext('mollie', 'Live')),
                             ('test', pgettext('mollie', 'Testing')),
                         ),
                     )),
                ]
            else:
                return {}
        else:
            fields = [
                ('api_key',
                 forms.CharField(
                     label=_('Secret key'),
                     validators=(
                         MollieKeyValidator(['live_', 'test_']),
                     ),
                     widget=SecretKeyInput(secret_key=self.settings.api_key or ''),
                     required=not bool(self.settings.api_key),
                 )),
            ]

        help_text_order_based = format_html(
            '<span class="fa fa-info-circle"></span> {}',
            _('This payment method requires pretix to submit additional data to Mollie, including the full invoice '
              'address and the purchased products. Note that you might need to add this additional data transfer '
              'to your privacy policy.')
        )
        if 'orders.write' not in (self.settings.connect_scope or ''):
            help_text_order_based = format_html(
                '<span class="text-danger"><span class="fa fa-warning"></span> {}</span><br>' +  help_text_order_based,
                _('This payment method requires additional permissions on your Mollie account. Please reconnect this '
                  'event with Mollie using the button below.')
            )

        if not self.event.settings.invoice_address_required:
            help_text_order_based = format_html(
                help_text_order_based + '<br><span class="fa fa-warning"></span> {}',
                _('This payment method will be unavailable if no invoice address has been entered, so consider making '
                  'this required.'),
            )
        help_text_order_based_financing = format_html(
            help_text_order_based + '<br><span class="fa fa-warning"></span> {}',
            _('This payment method includes a financing component, i.e. the user has to pay after the services have '
              'been delivered. pretix will mark the order as "delivered" right after the payment has been started since '
              'pretix is built for digital ticketing. Depending on the type of service you sell, this might not be '
              'in line with the payment provider\'s terms, so please carefully review the legal situation around this.')
        )

        d = OrderedDict(
            fields + [
                ('method_creditcard',
                 forms.BooleanField(
                     label=_('Credit card'),
                     required=False,
                 )),
                ('method_applepay',
                 forms.BooleanField(
                     label=_('Apple Pay'),
                     required=False,
                 )),
                ('method_bancontact',
                 forms.BooleanField(
                     label=_('Bancontact'),
                     required=False,
                 )),
                ('method_belfius',
                 forms.BooleanField(
                     label=_('Belfius Pay Button'),
                     required=False,
                 )),
                ('method_bitcoin',
                 forms.BooleanField(
                     label=_('Bitcoin'),
                     required=False,
                 )),
                ('method_eps',
                 forms.BooleanField(
                     label=_('EPS'),
                     required=False,
                 )),
                ('method_giropay',
                 forms.BooleanField(
                     label=_('giropay'),
                     required=False,
                 )),
                ('method_ideal',
                 forms.BooleanField(
                     label=_('iDEAL'),
                     required=False,
                 )),
                ('method_inghomepay',
                 forms.BooleanField(
                     label=_('ING Home’Pay'),
                     required=False,
                 )),
                ('method_kbc',
                 forms.BooleanField(
                     label=_('KBC/CBC Payment Button'),
                     required=False,
                 )),
                ('method_paysafecard',
                 forms.BooleanField(
                     label=_('paysafecard'),
                     required=False,
                 )),
                ('method_sofort',
                 forms.BooleanField(
                     label=_('SOFORT (instant bank transfer)'),
                     required=False,
                 )),
                ('method_paypal',
                 forms.BooleanField(
                     label=_('PayPal'),
                     required=False,
                 )),
                ('method_przelewy24',
                 forms.BooleanField(
                     label=_('Przelewy24'),
                     required=False,
                 )),
                ('method_banktransfer',
                 forms.BooleanField(
                     label=_('Bank transfer'),
                     required=False,
                 )),
                ('method_banktransfer_availability_date',
                 RelativeDateField(
                     label=_('Bank transfer available until'),
                     help_text=_('Users will not be able to choose this payment provider after the given date.'),
                     required=False,
                     widget=RelativeDateWidget(
                         status_choices=[
                             ('unset', _('Not set')),
                             ('absolute', _('Fixed date:')),
                             ('relative', _('Relative date:')),
                         ],
                         base_choices=BASE_CHOICES,
                         attrs={
                             "data-display-dependency": "#id_payment_mollie_method_banktransfer",
                         }
                     )
                 )),
                ('method_banktransfer_invoice_immediately',
                 forms.BooleanField(
                     label=_('Create an invoice for orders using bank transfer immediately if the event is otherwise '
                             'configured to create invoices after payment is completed.'),
                     required=False,
                     widget=forms.CheckboxInput(
                         attrs={
                             "data-display-dependency": "#id_payment_mollie_method_banktransfer",
                         }
                     ),
                 )),
                ('method_klarnapaynow',
                 forms.BooleanField(
                     label=_('Klarna Pay now'),
                     help_text=help_text_order_based,
                     required=False,
                 )),
                ('method_klarnapaylater',
                 forms.BooleanField(
                     label=_('Klarna Pay later'),
                     help_text=help_text_order_based_financing,
                     required=False,
                 )),
                ('method_klarnasliceit',
                 forms.BooleanField(
                     label=_('Klarna Slice it'),
                     help_text=help_text_order_based_financing,
                     required=False,
                 )),
                ('method_in3',
                 forms.BooleanField(
                     label=_('in3'),
                     help_text=help_text_order_based_financing,
                     required=False,
                 )),
                ('product_type',
                 forms.ChoiceField(
                     label=_('Product type'),
                     choices=(
                         ('digital', _('Digital product')),
                         ('physical', _('Physical product')),
                     ),
                     help_text=_('This is required information for payment methods like Klarna or in3.'),
                     required=True,
                 )),
            ] + list(super().settings_form_fields.items())
        )
        d['_availability_date'].label = _('All payment methods available until')
        d.move_to_end('_enabled', last=False)
        return d

    def settings_form_clean(self, cleaned_data):
        data = super().settings_form_clean(cleaned_data)
        if not data.get('payment_mollie_api_key'):
            data['payment_mollie_api_key'] = self.settings.api_key
        return data


class MollieMethod(BasePaymentProvider):
    method = ''
    abort_pending_allowed = False
    refunds_allowed = True

    def __init__(self, event: Event):
        super().__init__(event)
        self.settings = SettingsSandbox('payment', 'mollie', event)

    def _is_available_by_time(self, now_dt=None, cart_id=None, order=None):
        now_dt = now_dt or now()
        tz = pytz.timezone(self.event.settings.timezone)

        if not super()._is_available_by_time(now_dt, cart_id, order):
            return False

        availability_end = self._absolute_availability_date(
            self.settings.get(f'method_{self.method}_availability_date', as_type=RelativeDateWrapper),
            cart_id,
            order,
            aggregate_fn=min
        )
        if availability_end and availability_end < now_dt.astimezone(tz).date():
            return False

        return True

    @property
    def settings_form_fields(self):
        return {}

    @property
    def identifier(self):
        return 'mollie_{}'.format(self.method)

    @property
    def is_enabled(self) -> bool:
        return self.settings.get('_enabled', as_type=bool) and self.settings.get('method_{}'.format(self.method),
                                                                                 as_type=bool)

    def payment_refund_supported(self, payment: OrderPayment) -> bool:
        return self.refunds_allowed

    def payment_partial_refund_supported(self, payment: OrderPayment) -> bool:
        return self.refunds_allowed

    def payment_prepare(self, request, payment):
        return self.checkout_prepare(request, None)

    def payment_is_valid_session(self, request: HttpRequest):
        return True

    @property
    def request_headers(self):
        headers = {}
        if self.settings.connect_client_id and self.settings.access_token:
            headers['Authorization'] = 'Bearer %s' % self.settings.access_token
        else:
            headers['Authorization'] = 'Bearer %s' % self.settings.api_key
        return headers

    def payment_form_render(self, request) -> str:
        template = get_template('pretix_mollie/checkout_payment_form.html')
        ctx = {'request': request, 'event': self.event, 'settings': self.settings}
        return template.render(ctx)

    def checkout_confirm_render(self, request) -> str:
        template = get_template('pretix_mollie/checkout_payment_confirm.html')
        ctx = {'request': request, 'event': self.event, 'settings': self.settings, 'provider': self}
        return template.render(ctx)

    def payment_can_retry(self, payment):
        return self._is_still_available(order=payment.order)

    def payment_pending_render(self, request, payment) -> str:
        if payment.info:
            payment_info = json.loads(payment.info)
        else:
            payment_info = None
        template = get_template('pretix_mollie/pending.html')
        ctx = {
            'request': request,
            'event': self.event,
            'settings': self.settings,
            'provider': self,
            'order': payment.order,
            'payment': payment,
            'payment_info': payment_info,
        }
        return template.render(ctx)

    def payment_control_render(self, request, payment) -> str:
        if payment.info:
            payment_info = json.loads(payment.info)
        else:
            payment_info = None
        template = get_template('pretix_mollie/control.html')
        ctx = {
            'request': request,
            'event': self.event,
            'settings': self.settings,
            'payment_info': payment_info,
            'payment': payment,
            'method': self.method,
            'provider': self,
        }
        return template.render(ctx)

    def get_locale(self, language):
        pretix_to_mollie_locales = {
            'en': 'en_US',
            'nl': 'nl_NL',
            'nl_BE': 'nl_BE',
            'fr': 'fr_FR',
            'de': 'de_DE',
            'es': 'es_ES',
            'ca': 'ca_ES',
            'pt': 'pt_PT',
            'it': 'it_IT',
            'nb': 'nb_NO',
            'sv': 'sv_SE',
            'fi': 'fi_FI',
            'da': 'da_DK',
            'is': 'is_IS',
            'hu': 'hu_HU',
            'pl': 'pl_PL',
            'lv': 'lv_LV',
            'lt': 'lt_LT'
        }
        return pretix_to_mollie_locales.get(
            language,
            pretix_to_mollie_locales.get(
                language.split('-')[0],
                pretix_to_mollie_locales.get(
                    language.split('_')[0],
                    'en'
                )
            )
        )

    def redirect(self, request, url):
        if request.session.get('iframe_session', False):
            return (
                    build_absolute_uri(request.event, 'plugins:pretix_mollie:redirect') +
                    '?data=' + signing.dumps({
                'url': url,
                'session': {
                    'payment_mollie_order_secret': request.session['payment_mollie_order_secret'],
                },
            }, salt='safe-redirect')
            )
        else:
            return str(url)

    def shred_payment_info(self, obj: OrderPayment):
        if not obj.info:
            return
        d = json.loads(obj.info)
        if 'details' in d:
            d['details'] = {
                k: '█' for k in d['details'].keys()
                if k not in ('bitcoinAmount', )
            }

        d['_shredded'] = True
        obj.info = json.dumps(d)
        obj.save(update_fields=['info'])


class MolliePaymentMethod(MollieMethod):
    def _get_payment_body(self, payment):
        b = {
            'amount': {
                'currency': self.event.currency,
                'value': str(payment.amount),
            },
            'description': 'Order {}-{}'.format(self.event.slug.upper(), payment.full_id),
            'redirectUrl': build_absolute_uri(self.event, 'plugins:pretix_mollie:return', kwargs={
                'order': payment.order.code,
                'payment': payment.pk,
                'hash': hashlib.sha1(payment.order.secret.lower().encode()).hexdigest(),
            }),
            'webhookUrl': build_absolute_uri(self.event, 'plugins:pretix_mollie:webhook', kwargs={
                'payment': payment.pk
            }),
            'locale': self.get_locale(payment.order.locale),
            'method': self.method,
            'metadata': {
                'organizer': self.event.organizer.slug,
                'event': self.event.slug,
                'order': payment.order.code,
                'payment': payment.local_id,
            }
        }
        if self.settings.connect_client_id and self.settings.access_token:
            b['profileId'] = self.settings.connect_profile
            b['testmode'] = self.settings.endpoint == 'test' or self.event.testmode
        return b

    def execute_payment(self, request: HttpRequest, payment: OrderPayment, retry=True):
        try:
            if '_links' in payment.info_data:
                if request:
                    return self.redirect(request, payment.info_data.get('_links').get('checkout').get('href'))
                else:
                    return
        except:
            pass
        try:
            refresh_mollie_token(self.event, True)
            req = requests.post(
                'https://api.mollie.com/v2/payments',
                json=self._get_payment_body(payment),
                headers=self.request_headers
            )
            req.raise_for_status()
        except HTTPError:
            logger.exception('Mollie error: %s' % req.text)
            try:
                d = req.json()

                if d.get('status') == 401 and retry:
                    # Token might be expired, let's retry!
                    if refresh_mollie_token(self.event, False):
                        return self.execute_payment(request, payment, retry=False)
            except:
                d = {
                    'error': True,
                    'detail': req.text
                }
            payment.fail(info=d)
            raise PaymentException(_('We had trouble communicating with Mollie. Please try again and get in touch '
                                     'with us if this problem persists.'))

        data = req.json()
        payment.info = json.dumps(data)
        payment.state = OrderPayment.PAYMENT_STATE_CREATED
        payment.save()
        if request:
            request.session['payment_mollie_order_secret'] = payment.order.secret
            return self.redirect(request, data.get('_links').get('checkout').get('href'))
        else:
            return

    def execute_refund(self, refund: OrderRefund, retry=True):
        payment = refund.payment.info_data.get('id')
        body = {
            'amount': {
                'currency': self.event.currency,
                'value': str(refund.amount)
            },
        }
        if self.settings.connect_client_id and self.settings.access_token:
            body['testmode'] = refund.payment.info_data.get('mode', 'live') == 'test'
        try:
            refresh_mollie_token(self.event, True)
            req = requests.post(
                'https://api.mollie.com/v2/payments/{}/refunds'.format(payment),
                json=body,
                headers=self.request_headers
            )
            req.raise_for_status()
            refund.info_data = req.json()
        except HTTPError:
            logger.exception('Mollie error: %s' % req.text)
            try:
                refund.info_data = req.json()

                if payment.info_data.get('status') == 401 and retry:
                    # Token might be expired, let's retry!
                    if refresh_mollie_token(self.event, False):
                        return self.execute_refund(refund, retry=False)
            except:
                refund.info_data = {
                    'error': True,
                    'detail': req.text
                }
            raise PaymentException(_('Mollie reported an error: {}').format(refund.info_data.get('detail')))
        else:
            refund.done()


class MollieOrderMethod(MollieMethod):

    def _get_order_body(self, payment):
        try:
            ia = payment.order.invoice_address
            first_name = ia.name_parts.get('given_name') or ia.name.rsplit(' ', 1)[0] or 'Unknown'
            last_name = ia.name_parts.get('family_name') or ia.name.rsplit(' ', 1)[-1] or 'Unknown'
            if not ia.street or not ia.city or not ia.country or not payment.order.email:
                raise PaymentException(_("This payment method can only be used if a full invoice address and an "
                                         "email address has been entered."))
        except InvoiceAddress.DoesNotExist:
            raise PaymentException(_("This payment method can only be used if a full invoice address and an "
                                     "email address has been entered."))

        lines = []
        for op in payment.order.positions.all():
            lines.append({
                'type': self.settings.product_type,
                'name': str(op.item.name),
                'quantity': 1,
                'unitPrice': {
                    'currency': self.event.currency,
                    'value': str(op.price),
                },
                'totalAmount': {
                    'currency': self.event.currency,
                    'value': str(op.price),
                },
                'vatRate': str(op.tax_rate or '0.00'),
                'vatAmount': {
                    'currency': self.event.currency,
                    'value': str(op.tax_value),
                },
                'sku': f'{self.event.slug}-{op.item_id}-{op.variation_id or 0}',
            })

        for of in payment.order.fees.all():
            lines.append({
                'type': 'shipping_fee' if of.fee_type == OrderFee.FEE_TYPE_SHIPPING else 'surcharge',
                'name': of.get_fee_type_display(),
                'quantity': 1,
                'unitPrice': {
                    'currency': self.event.currency,
                    'value': str(of.value),
                },
                'totalAmount': {
                    'currency': self.event.currency,
                    'value': str(of.value),
                },
                'vatRate': str(of.tax_rate or '0.00'),
                'vatAmount': {
                    'currency': self.event.currency,
                    'value': str(of.tax_value),
                },
                'sku': f'{self.event.slug}-{of.fee_type}-{of.internal_type}',
            })

        if payment.order.total != payment.amount:
            lines.append({
                'type': 'gift_card',
                'name': str(_('Other payment methods')),
                'quantity': 1,
                'unitPrice': {
                    'currency': self.event.currency,
                    'value': str(payment.amount - payment.order.total),
                },
                'totalAmount': {
                    'currency': self.event.currency,
                    'value': str(payment.amount - payment.order.total),
                },
                'vatRate': '0.00',
                'vatAmount': {
                    'currency': self.event.currency,
                    'value': '0.00',
                },
            })

        b = {
            'amount': {
                'currency': self.event.currency,
                'value': str(payment.amount),
            },
            'orderNumber': '{}-{}'.format(self.event.slug.upper(), payment.full_id),
            'billingAddress': {
                'organizationName': ia.company or None,
                'title': ia.name_parts.get('title'),
                'givenName': first_name,
                'familyName': last_name,
                'email': payment.order.email,
                'phone': str(payment.order.phone) if payment.order.phone else None,
                'streetAndNumber': ia.street,
                'postalCode': ia.zipcode,
                'city': ia.city,
                'country': str(ia.country),
            },
            'lines': lines,
            'redirectUrl': build_absolute_uri(self.event, 'plugins:pretix_mollie:return', kwargs={
                'order': payment.order.code,
                'payment': payment.pk,
                'hash': hashlib.sha1(payment.order.secret.lower().encode()).hexdigest(),
            }),
            'webhookUrl': build_absolute_uri(self.event, 'plugins:pretix_mollie:webhook', kwargs={
                'payment': payment.pk
            }),
            'locale': self.get_locale(payment.order.locale),
            'method': self.method,
            'metadata': {
                'organizer': self.event.organizer.slug,
                'event': self.event.slug,
                'order': payment.order.code,
                'payment': payment.local_id,
            }
        }
        if self.settings.connect_client_id and self.settings.access_token:
            b['profileId'] = self.settings.connect_profile
            b['testmode'] = self.settings.endpoint == 'test' or self.event.testmode
        return b

    def payment_form_render(self, request) -> str:
        template = get_template('pretix_mollie/checkout_payment_form_order.html')
        ctx = {'request': request, 'event': self.event, 'settings': self.settings}
        return template.render(ctx)

    def is_allowed(self, request: HttpRequest, total=None) -> bool:
        parent_allowed = super().is_allowed(request, total)

        if parent_allowed:
            def get_invoice_address():
                if not hasattr(request, '_checkout_flow_invoice_address'):
                    cs = cart_session(request)
                    iapk = cs.get('invoice_address')
                    if not iapk:
                        request._checkout_flow_invoice_address = InvoiceAddress()
                    else:
                        try:
                            request._checkout_flow_invoice_address = InvoiceAddress.objects.get(pk=iapk, order__isnull=True)
                        except InvoiceAddress.DoesNotExist:
                            request._checkout_flow_invoice_address = InvoiceAddress()
                return request._checkout_flow_invoice_address

            ia = get_invoice_address()
            if not ia or not ia.country or not ia.zipcode or not ia.city or not ia.street or not ia.name:
                return False

        return parent_allowed

    def order_change_allowed(self, order: Order, request: HttpRequest=None) -> bool:
        parent_allowed = super().order_change_allowed(order, request)

        if parent_allowed:
            try:
                ia = order.invoice_address
                if not order.email or not ia or not ia.country or not ia.zipcode or not ia.city or not ia.street or not ia.name:
                    return False
            except InvoiceAddress.DoesNotExist:
                return False

        return parent_allowed

    def execute_payment(self, request: HttpRequest, payment: OrderPayment, retry=True):
        try:
            if '_links' in payment.info_data:
                if request:
                    return self.redirect(request, payment.info_data.get('_links').get('checkout').get('href'))
                else:
                    return
        except:
            pass
        try:
            refresh_mollie_token(self.event, True)
            req = requests.post(
                'https://api.mollie.com/v2/orders',
                json=self._get_order_body(payment),
                headers=self.request_headers
            )
            req.raise_for_status()
        except HTTPError:
            logger.exception('Mollie error: %s' % req.text)
            try:
                d = req.json()

                if d.get('status') == 401 and retry:
                    # Token might be expired, let's retry!
                    if refresh_mollie_token(self.event, False):
                        return self.execute_payment(request, payment, retry=False)
            except:
                d = {
                    'error': True,
                    'detail': req.text
                }
            payment.fail(info=d)
            raise PaymentException(_('We had trouble communicating with Mollie. Please try again and get in touch '
                                     'with us if this problem persists.'))

        data = req.json()
        payment.info = json.dumps(data)
        payment.state = OrderPayment.PAYMENT_STATE_CREATED
        payment.save()
        if request:
            request.session['payment_mollie_order_secret'] = payment.order.secret
            return self.redirect(request, data.get('_links').get('checkout').get('href'))
        else:
            return

    def payment_partial_refund_supported(self, payment: OrderPayment) -> bool:
        return False

    def execute_refund(self, refund: OrderRefund, retry=True):
        order = refund.payment.info_data.get('id')
        body = {
            'lines': [],  # " If you send an empty array, the entire order will be refunded."
        }
        if self.settings.connect_client_id and self.settings.access_token:
            body['testmode'] = refund.payment.info_data.get('mode', 'live') == 'test'
        try:
            refresh_mollie_token(self.event, True)
            req = requests.post(
                'https://api.mollie.com/v2/orders/{}/refunds'.format(order),
                json=body,
                headers=self.request_headers
            )
            req.raise_for_status()
            refund.info_data = req.json()
        except HTTPError:
            logger.exception('Mollie error: %s' % req.text)
            try:
                refund.info_data = req.json()

                if refund.info_data.get('status') == 401 and retry:
                    # Token might be expired, let's retry!
                    if refresh_mollie_token(self.event, False):
                        return self.execute_refund(refund, retry=False)
            except:
                refund.info_data = {
                    'error': True,
                    'detail': req.text
                }
            raise PaymentException(_('Mollie reported an error: {}').format(refund.info_data.get('detail')))
        else:
            refund.amount = Decimal(refund.info_data["amount"]["value"])
            refund.done()


class MollieCC(MolliePaymentMethod):
    method = 'creditcard'
    verbose_name = _('Credit card via Mollie')
    public_name = _('Credit card')


class MollieBancontact(MolliePaymentMethod):
    method = 'bancontact'
    verbose_name = _('Bancontact via Mollie')
    public_name = _('Bancontact')


class MollieBanktransfer(MolliePaymentMethod):
    method = 'banktransfer'
    verbose_name = _('Bank transfer via Mollie')
    public_name = _('Bank transfer')

    @property
    def requires_invoice_immediately(self):
        return self.settings.get('method_banktransfer_invoice_immediately', False, as_type=bool)

    def execute_payment(self, request: HttpRequest, payment: OrderPayment, retry=True):
        err = None
        with transaction.atomic():
            p_orig = payment
            if retry:
                payment = OrderPayment.objects.select_for_update(of=OF_SELF).get(pk=payment.pk)
            try:
                super().execute_payment(request, payment, retry)
            except PaymentException as e:
                err = e
        if err:
            raise err

        p_orig.refresh_from_db()
        return  # no redirect necessary for this method

    def _get_payment_body(self, payment):
        body = super()._get_payment_body(payment)
        body['dueDate'] = (payment.order.expires.date() + timedelta(days=1)).isoformat()
        return body

    def order_pending_mail_render(self, order, payment) -> str:
        if payment.state == OrderPayment.PAYMENT_STATE_CREATED and not payment.info:
            try:
                self.execute_payment(None, payment)
            except:
                logger.exception('Could not execute payment')

        if payment.info:
            payment_info = json.loads(payment.info)
        else:
            return ""
        if 'details' not in payment_info:
            return ""

        template = get_template('pretix_mollie/order_pending.txt')
        bankdetails = [
            _("Account holder"), ": ", payment_info['details'].get('bankName', '?'), "\n",
            _("IBAN"), ": ", payment_info['details'].get('bankAccount', '?'), "\n",
            _("BIC"), ": ", payment_info['details'].get('bankBic', '?'),
        ]
        ctx = {
            'event': self.event,
            'code': payment_info['details'].get('transferReference', '?'),
            'amount': payment.amount,
            'details': textwrap.indent(''.join(str(i) for i in bankdetails), '    '),
        }
        return template.render(ctx)

    def render_invoice_text(self, order: Order, payment: OrderPayment) -> str:
        if order.status == Order.STATUS_PAID:
            return super().render_invoice_text(order, payment)

        if payment.state == OrderPayment.PAYMENT_STATE_CREATED and not payment.info:
            try:
                self.execute_payment(None, payment)
            except:
                logger.exception('Could not execute payment')

        t = self.settings.get('_invoice_text', as_type=LazyI18nString, default='')

        if payment.info:
            payment_info = json.loads(payment.info)
        else:
            return t
        if 'details' not in payment_info:
            return t

        bankdetails = [
            _("Please transfer the invoice amount to the bank account of our payment service provider "
              "using the specified reference:"),
            "\n",
            _("Account holder"), ": ", payment_info['details'].get('bankName', '?'), "\n",
            _("IBAN"), ": ", payment_info['details'].get('bankAccount', ''), "\n",
            _("BIC"), ": ", payment_info['details'].get('bankBic', '?'), "\n",
            _("Reference"), ": ", payment_info['details'].get('transferReference', '?'),
            "\n",
            _("Please only use the given reference. Otherwise, your payment can not be processed."),
        ]
        if t:
            bankdetails += ['\n', t]
        return ''.join(str(i) for i in bankdetails)

    def payment_form_render(self, request) -> str:
        template = get_template('pretix_mollie/checkout_payment_form_banktransfer.html')
        ctx = {'request': request, 'event': self.event, 'settings': self.settings}
        return template.render(ctx)


class MollieBelfius(MolliePaymentMethod):
    method = 'belfius'
    verbose_name = _('Belfius Pay Button via Mollie')
    public_name = _('Belfius')


class MollieBitcoin(MolliePaymentMethod):
    method = 'bitcoin'
    verbose_name = _('Bitcoin via Mollie')
    public_name = _('Bitcoin')
    refunds_allowed = False


class MollieEPS(MolliePaymentMethod):
    method = 'eps'
    verbose_name = _('EPS via Mollie')
    public_name = _('eps')


class MollieGiropay(MolliePaymentMethod):
    method = 'giropay'
    verbose_name = _('giropay via Mollie')
    public_name = _('giropay')


class MollieIdeal(MolliePaymentMethod):
    method = 'ideal'
    verbose_name = _('iDEAL via Mollie')
    public_name = _('iDEAL')


class MollieINGHomePay(MolliePaymentMethod):
    method = 'inghomepay'
    verbose_name = _('ING Home’Pay via Mollie')
    public_name = _('ING Home’Pay')


class MollieKBC(MolliePaymentMethod):
    method = 'kbc'
    verbose_name = _('KBC/CBC Payment Button via Mollie')
    public_name = _('KBC/CBC')


class MolliePaysafecard(MolliePaymentMethod):
    method = 'paysafecard'
    verbose_name = _('paysafecard via Mollie')
    public_name = _('paysafecard')
    refunds_allowed = False


class MollieSofort(MolliePaymentMethod):
    method = 'sofort'
    verbose_name = _('SOFORT via Mollie')
    public_name = _('SOFORT (instant bank transfer)')


class MolliePayPal(MolliePaymentMethod):
    method = 'paypal'
    verbose_name = _('PayPal via Mollie')
    public_name = _('PayPal')


class MolliePrzelewy24(MolliePaymentMethod):
    method = 'przelewy24'
    verbose_name = _('Przelewy24 via Mollie')
    public_name = _('Przelewy24')


class MollieApplePay(MolliePaymentMethod):
    method = 'applepay'
    verbose_name = _('Apple Pay via Mollie')
    public_name = _('Apple Pay')


class MollieKlarnaPaynow(MollieOrderMethod):
    method = 'klarnapaynow'
    verbose_name = _('Klarna Pay now via Mollie')
    public_name = _('Klarna Pay now')


class MollieKlarnaPaylater(MollieOrderMethod):
    method = 'klarnapaylater'
    verbose_name = _('Klarna Pay later via Mollie')
    public_name = _('Klarna Pay later')


class MollieKlarnaSliceit(MollieOrderMethod):
    method = 'klarnasliceit'
    verbose_name = _('Klarna Slice it via Mollie')
    public_name = _('Klarna Slice it')


class MollieIn3(MollieOrderMethod):
    method = 'in3'
    verbose_name = _('in3 it via Mollie')
    public_name = _('in3')
