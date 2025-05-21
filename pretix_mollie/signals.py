import logging
from collections import OrderedDict
from django import forms
from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _
from pretix.base.forms import SecretKeySettingsField
from pretix.base.models import Event, Order, OrderPayment
from pretix.base.payment import PaymentException
from pretix.base.settings import settings_hierarkey
from pretix.base.signals import (
    logentry_display,
    order_expiry_changed,
    register_global_settings,
    register_payment_providers,
)

from .forms import MollieKeyValidator

logger = logging.getLogger(__name__)


@receiver(register_payment_providers, dispatch_uid="payment_mollie")
def register_payment_provider(sender, **kwargs):
    from .payment import (
        MollieAlma,
        MollieBancomatPay,
        MollieBancontact,
        MollieBanktransfer,
        MollieBelfius,
        MollieBitcoin,
        MollieBlik,
        MollieCC,
        MollieEPS,
        MollieGiropay,
        MollieIdeal,
        MollieIn3,
        MollieINGHomePay,
        MollieKBC,
        MollieKlarna,
        MollieKlarnaPaylater,
        MollieKlarnaPaynow,
        MollieKlarnaSliceit,
        MollieMyBank,
        MolliePayPal,
        MolliePaysafecard,
        MolliePrzelewy24,
        MollieSatispay,
        MollieSettingsHolder,
        MollieSofort,
        MollieTrustly,
        MollieTwint,
        MolliePayByBank,
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
        MolliePrzelewy24,
        MollieKlarna,
        MollieKlarnaPaynow,
        MollieKlarnaPaylater,
        MollieKlarnaSliceit,
        MollieIn3,
        MollieTwint,
        MollieTrustly,
        MollieBancomatPay,
        MollieMyBank,
        MollieBlik,
        MollieSatispay,
        MollieAlma,
        MolliePayByBank,
    ]


@receiver(signal=logentry_display, dispatch_uid="mollie_logentry_display")
def pretixcontrol_logentry_display(sender, logentry, **kwargs):
    if not logentry.action_type.startswith("pretix_mollie.event"):
        return

    plains = {
        "canceled": _("Payment canceled."),
        "failed": _("Payment failed."),
        "paid": _("Payment succeeded."),
        "expired": _("Payment expired."),
        "expiry_update_failed": _("Failed to update payment expiration date."),
        "disabled": _(
            "Payment method disabled since we were unable to refresh the access token. Please "
            "contact support."
        ),  # for historical reasons, no longer occurs
    }
    text = plains.get(logentry.action_type[20:], None)
    if text:
        return _("Mollie reported an event: {}").format(text)


settings_hierarkey.add_default("payment_mollie_method_cc", True, bool)
settings_hierarkey.add_default("payment_mollie_product_type", "digital", str)


@receiver(register_global_settings, dispatch_uid="mollie_global_settings")
def register_global_settings(sender, **kwargs):
    return OrderedDict(
        [
            (
                "payment_mollie_connect_client_id",
                forms.CharField(
                    label=_("Mollie Connect: Client ID"),
                    required=False,
                    validators=(MollieKeyValidator("app_"),),
                ),
            ),
            (
                "payment_mollie_connect_client_secret",
                SecretKeySettingsField(
                    label=_("Mollie Connect: Client secret"),
                    required=False,
                ),
            ),
        ]
    )


@receiver(order_expiry_changed, dispatch_uid="mollie_order_expiry_changed")
def order_modified(sender: Event, order: Order, **kwargs):
    payment = order.payments.last()
    if (
        payment
        and payment.provider == "mollie_banktransfer"
        and payment.state
        in [OrderPayment.PAYMENT_STATE_CREATED, OrderPayment.PAYMENT_STATE_PENDING]
    ):
        try:
            pprov = payment.payment_provider
            pprov.update_payment_expiry(payment)
        except PaymentException:
            payment.order.log_action(
                "pretix_mollie.event.expiry_update_failed",
                {
                    "local_id": payment.local_id,
                    "provider": payment.provider,
                },
            )
