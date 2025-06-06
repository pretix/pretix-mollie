import hashlib
import json
import logging
import requests
import time
import urllib.parse
from decimal import Decimal
from django.contrib import messages
from django.core import signing
from django.db import transaction
from django.http import Http404, HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django_scopes import scopes_disabled
from pretix.base.models import (
    Event, Event_SettingsStore, Order, OrderPayment, Quota,
)
from pretix.base.payment import PaymentException
from pretix.base.services.locking import LockTimeoutException
from pretix.base.settings import GlobalSettingsObject
from pretix.control.permissions import event_permission_required
from pretix.helpers import OF_SELF
from pretix.helpers.urls import build_absolute_uri as build_global_uri
from pretix.multidomain.urlreverse import build_absolute_uri, eventreverse
from requests import HTTPError

from pretix_mollie.utils import refresh_mollie_token

logger = logging.getLogger(__name__)


@xframe_options_exempt
def redirect_view(request, *args, **kwargs):
    try:
        data = signing.loads(request.GET.get("data", ""), salt="safe-redirect")
    except signing.BadSignature:
        return HttpResponseBadRequest("Invalid parameter")

    if "go" in request.GET:
        if "session" in data:
            for k, v in data["session"].items():
                request.session[k] = v
        return redirect(data["url"])
    else:
        params = request.GET.copy()
        params["go"] = "1"
        r = render(
            request,
            "pretix_mollie/redirect.html",
            {
                "url": build_absolute_uri(
                    request.event, "plugins:pretix_mollie:redirect"
                )
                + "?"
                + urllib.parse.urlencode(params),
            },
        )
        r._csp_ignore = True
        return r


@scopes_disabled()
def oauth_return(request, *args, **kwargs):
    if "payment_mollie_oauth_event" not in request.session:
        messages.error(
            request,
            _("An error occurred during connecting with Mollie, please try again."),
        )
        return redirect(reverse("control:index"))

    event = get_object_or_404(Event, pk=request.session["payment_mollie_oauth_event"])

    if request.GET.get("state") != request.session["payment_mollie_oauth_token"]:
        messages.error(
            request,
            _("An error occurred during connecting with Mollie, please try again."),
        )
        return redirect(
            reverse(
                "control:event.settings.payment.provider",
                kwargs={
                    "organizer": event.organizer.slug,
                    "event": event.slug,
                    "provider": "mollie",
                },
            )
        )

    gs = GlobalSettingsObject()

    try:
        resp = requests.post(
            "https://api.mollie.com/oauth2/tokens",
            auth=(
                gs.settings.payment_mollie_connect_client_id,
                gs.settings.payment_mollie_connect_client_secret,
            ),
            data={
                "grant_type": "authorization_code",
                "code": request.GET.get("code"),
                "redirect_uri": build_global_uri("plugins:pretix_mollie:oauth.return"),
            },
        )
        resp.raise_for_status()
        data = resp.json()

        if "error" not in data:
            orgaresp = requests.get(
                "https://api.mollie.com/v2/organizations/me",
                headers={"Authorization": "Bearer " + data.get("access_token")},
            )
            orgaresp.raise_for_status()
            orgadata = orgaresp.json()

            profilesurl = "https://api.mollie.com/v2/profiles"
            profiles = []
            while profilesurl:
                profilesresp = requests.get(
                    profilesurl,
                    headers={"Authorization": "Bearer " + data.get("access_token")},
                )
                profilesresp.raise_for_status()
                d = profilesresp.json()
                profiles += d["_embedded"]["profiles"]
                if d["_links"]["next"]:
                    profilesurl = d["_links"]["next"]["href"]
                else:
                    profilesurl = None
    except Exception:
        logger.exception("Failed to obtain OAuth token")
        messages.error(
            request,
            _("An error occurred during connecting with Mollie, please try again."),
        )
    else:
        if "error" in data:
            messages.error(
                request,
                _("Mollie returned an error: {}").format(data["error_description"]),
            )
        elif not profiles:
            messages.error(
                request,
                _(
                    "Please create a website profile in your Mollie account and try again."
                ),
            )
        elif not orgadata.get("id", "") or not orgadata.get("name", ""):
            messages.error(
                request,
                _(
                    "Please fill in your company details in your Mollie account and try again."
                ),
            )
        else:
            messages.success(
                request,
                _(
                    "Your Mollie account is now connected to pretix. You can change the settings in "
                    "detail below."
                ),
            )

            old_org_id = event.settings.payment_mollie_connect_org_id
            old_refresh_token = event.settings.payment_mollie_refresh_token

            def _set_settings(ev):
                ev.settings.payment_mollie_access_token = data["access_token"]
                ev.settings.payment_mollie_refresh_token = data["refresh_token"]
                ev.settings.payment_mollie_expires = time.time() + data["expires_in"]
                ev.settings.payment_mollie_connect_scope = data["scope"]
                ev.settings.payment_mollie_connect_org_id = orgadata.get("id")
                ev.settings.payment_mollie_connect_org_name = orgadata.get("name", "")
                ev.settings.payment_mollie_connect_profiles = [
                    [p.get("id"), p.get("name") + " - " + p.get("website", "")]
                    for p in profiles
                ]
                valid_ids = [p.get("id") for p in profiles]
                if ev.settings.payment_mollie_connect_profile not in valid_ids:
                    ev.settings.payment_mollie_connect_profile = valid_ids[0]

            _set_settings(event)

            # This is the same account as previously connected, let's also update all other events connected with the
            # same mollie org.
            if old_refresh_token and old_org_id == orgadata.get("id"):
                for ev in Event_SettingsStore.objects.filter(
                    key="payment_mollie_refresh_token", value=old_refresh_token
                ):
                    _set_settings(ev.object)

            if request.session.get("payment_mollie_oauth_enable", False):
                event.settings.payment_mollie__enabled = True
                del request.session["payment_mollie_oauth_enable"]

    return redirect(
        reverse(
            "control:event.settings.payment.provider",
            kwargs={
                "organizer": event.organizer.slug,
                "event": event.slug,
                "provider": "mollie",
            },
        )
    )


def get_or_create_payment(payment, mollie_id, data):
    if payment.info_data.get("id") != mollie_id:
        for op in OrderPayment.objects.filter(order=payment.order, provider=payment.provider):
            if payment.info_data.get("id") == mollie_id:
                return op
        else:
            payment = OrderPayment(
                order=payment.order,
                amount=Decimal(data.get("amount", {}).get("value", 0)),
                provider=payment.provider,
                state=OrderPayment.PAYMENT_STATE_CREATED,
                info_data=data,
            )
            payment.save()

    return payment


def handle_payment(payment, mollie_id, retry=True):
    pprov = payment.payment_provider

    if (
        pprov.settings.connect_client_id
        and payment.info_data
        and payment.info_data.get("mode", "live") == "test"
    ):
        qp = "testmode=true"
    elif (
        pprov.settings.connect_client_id
        and pprov.settings.access_token
        and pprov.settings.endpoint == "test"
    ):
        qp = "testmode=true"
    else:
        qp = ""
    try:
        refresh_mollie_token(payment.order.event, True)
        resp = requests.get(
            "https://api.mollie.com/v2/payments/" + mollie_id + "?" + qp,
            headers=pprov.request_headers,
        )
        resp.raise_for_status()
        data = resp.json()

        payment = get_or_create_payment(payment, mollie_id, data)

        if data.get("amountRefunded") and data["amountRefunded"].get("value") != "0.00" and data.get("status") == "paid":
            refundsresp = requests.get(
                "https://api.mollie.com/v2/payments/" + mollie_id + "/refunds?" + qp,
                headers=pprov.request_headers,
            )
            refundsresp.raise_for_status()
            refunds = refundsresp.json()["_embedded"]["refunds"]
        else:
            refunds = []

        if data.get("amountChargedBack") and data["amountChargedBack"].get("value") != "0.00" and data.get("status") == "paid":
            chargebacksresp = requests.get(
                "https://api.mollie.com/v2/payments/"
                + mollie_id
                + "/chargebacks?"
                + qp,
                headers=pprov.request_headers,
            )
            chargebacksresp.raise_for_status()
            chargebacks = chargebacksresp.json()["_embedded"]["chargebacks"]
        else:
            chargebacks = []

        payment.info = json.dumps(data)
        payment.save()

        if data.get("status") == "paid" and payment.state in (
            OrderPayment.PAYMENT_STATE_PENDING,
            OrderPayment.PAYMENT_STATE_CREATED,
            OrderPayment.PAYMENT_STATE_CANCELED,
            OrderPayment.PAYMENT_STATE_FAILED,
        ):
            payment.order.log_action("pretix_mollie.event.paid")
            payment.confirm()
        elif data.get("status") == "canceled" and payment.state in (
            OrderPayment.PAYMENT_STATE_CREATED,
            OrderPayment.PAYMENT_STATE_PENDING,
        ):
            payment.state = OrderPayment.PAYMENT_STATE_CANCELED
            payment.save()
            payment.order.log_action("pretix_mollie.event.canceled")
        elif (
            data.get("status") == "pending"
            and payment.state == OrderPayment.PAYMENT_STATE_CREATED
        ):
            payment.state = OrderPayment.PAYMENT_STATE_PENDING
            payment.save()
        elif data.get("status") in ("expired", "failed") and payment.state in (
            OrderPayment.PAYMENT_STATE_CREATED,
            OrderPayment.PAYMENT_STATE_PENDING,
        ):
            payment.fail(log_data={"status": data.get("status")})
        elif payment.state == OrderPayment.PAYMENT_STATE_CONFIRMED:
            known_refunds = [r.info_data.get("id") for r in payment.refunds.all()]
            for r in refunds:
                if r.get("status") != "failed" and r.get("id") not in known_refunds:
                    payment.create_external_refund(
                        amount=Decimal(r["amount"]["value"]), info=json.dumps(r)
                    )
            for r in chargebacks:
                if r.get("id") not in known_refunds:
                    payment.create_external_refund(
                        amount=Decimal(r["amount"]["value"]), info=json.dumps(r)
                    )
        else:
            payment.order.log_action("pretix_mollie.event.unknown", data)
    except HTTPError:
        if resp.status_code == 401 and retry:
            # Token might be expired, let's retry!
            if refresh_mollie_token(payment.order.event, False):
                return handle_payment(payment, mollie_id, retry=False)
        raise PaymentException(
            _(
                "We had trouble communicating with Mollie. Please try again and get in touch "
                "with us if this problem persists."
            )
        )


def handle_order(payment, mollie_id, retry=True):
    pprov = payment.payment_provider
    if (
        pprov.settings.connect_client_id
        and payment.info_data
        and payment.info_data.get("mode", "live") == "test"
    ):
        qp = "testmode=true"
    elif (
        pprov.settings.connect_client_id
        and pprov.settings.access_token
        and pprov.settings.endpoint == "test"
    ):
        qp = "testmode=true"
    else:
        qp = ""
    try:
        refresh_mollie_token(payment.order.event, True)
        resp = requests.get(
            "https://api.mollie.com/v2/orders/" + mollie_id + "?" + qp,
            headers=pprov.request_headers,
        )
        resp.raise_for_status()
        data = resp.json()

        payment = get_or_create_payment(payment, mollie_id, data)

        if data.get("status") in ("paid", "shipping", "completed") and any(
            line["amountRefunded"].get("value", "0.00") != "0.00"
            for line in data["lines"]
        ):
            refundsresp = requests.get(
                "https://api.mollie.com/v2/orders/" + mollie_id + "/refunds?" + qp,
                headers=pprov.request_headers,
            )
            refundsresp.raise_for_status()
            refunds = refundsresp.json()["_embedded"]["refunds"]
        else:
            refunds = []

        payment.info = json.dumps(data)
        payment.save()

        if (
            data.get("status") in ("authorized", "paid", "shipping")
            and payment.state == OrderPayment.PAYMENT_STATE_CREATED
        ):  # todo: remove paid
            payment.order.log_action("pretix_mollie.event." + data["status"])
            with transaction.atomic():
                # Mark order as shipped
                payment = OrderPayment.objects.select_for_update(of=OF_SELF).get(pk=payment.pk)
                if payment.state != OrderPayment.PAYMENT_STATE_CREATED:
                    return  # race condition between return view and webhook

                body = {
                    # "If you leave out this parameter [lines], the entire order will be shipped."
                }

                if pprov.settings.connect_client_id and pprov.settings.access_token:
                    body["testmode"] = payment.info_data.get("mode", "live") == "test"

                resp = requests.post(
                    "https://api.mollie.com/v2/orders/" + mollie_id + "/shipments",
                    headers=pprov.request_headers,
                    json=body,
                )
                try:
                    resp.raise_for_status()
                except requests.HTTPError:
                    logger.exception(f"Could not confirm shipment, response was: {resp.text}")
                    raise
                payment.state = OrderPayment.PAYMENT_STATE_PENDING
                payment.save(update_fields=["state"])
            handle_order(payment, mollie_id)
        elif data.get("status") in ("paid", "completed") and payment.state in (
            OrderPayment.PAYMENT_STATE_PENDING,
            OrderPayment.PAYMENT_STATE_CREATED,
            OrderPayment.PAYMENT_STATE_CANCELED,
            OrderPayment.PAYMENT_STATE_FAILED,
        ):
            if Decimal(data["amountCaptured"]["value"]) != payment.amount:
                payment.amount = Decimal(data["amountCaptured"]["value"])
            payment.order.log_action("pretix_mollie.event.paid")
            payment.confirm()
        elif data.get("status") == "canceled" and payment.state in (
            OrderPayment.PAYMENT_STATE_CREATED,
            OrderPayment.PAYMENT_STATE_PENDING,
        ):
            payment.state = OrderPayment.PAYMENT_STATE_CANCELED
            payment.save()
            payment.order.log_action("pretix_mollie.event.canceled")
        elif (
            data.get("status") == "pending"
            and payment.state == OrderPayment.PAYMENT_STATE_CREATED
        ):
            payment.state = OrderPayment.PAYMENT_STATE_PENDING
            payment.save()
        elif data.get("status") in ("expired", "failed") and payment.state in (
            OrderPayment.PAYMENT_STATE_CREATED,
            OrderPayment.PAYMENT_STATE_PENDING,
        ):
            payment.fail(log_data={"status": data.get("status")})
        elif payment.state == OrderPayment.PAYMENT_STATE_CONFIRMED:
            known_refunds = [r.info_data.get("id") for r in payment.refunds.all()]
            for r in refunds:
                if r.get("status") != "failed" and r.get("id") not in known_refunds:
                    payment.create_external_refund(
                        amount=Decimal(r["amount"]["value"]), info=json.dumps(r)
                    )
        else:
            payment.order.log_action("pretix_mollie.event.unknown", data)
    except HTTPError:
        if resp.status_code == 401 and retry:
            # Token might be expired, let's retry!
            if refresh_mollie_token(payment.order.event, False):
                return handle_payment(payment, mollie_id, retry=False)
        raise PaymentException(
            _(
                "We had trouble communicating with Mollie. Please try again and get in touch "
                "with us if this problem persists."
            )
        )


@event_permission_required("can_change_event_settings")
@require_POST
def oauth_disconnect(request, **kwargs):
    del request.event.settings.payment_mollie_access_token
    del request.event.settings.payment_mollie_refresh_token
    del request.event.settings.payment_mollie_expires
    del request.event.settings.payment_mollie_connect_org_id
    del request.event.settings.payment_mollie_connect_org_name
    del request.event.settings.payment_mollie_connect_profiles
    request.event.settings.payment_mollie__enabled = False
    messages.success(request, _("Your Mollie account has been disconnected."))

    return redirect(
        reverse(
            "control:event.settings.payment.provider",
            kwargs={
                "organizer": request.event.organizer.slug,
                "event": request.event.slug,
                "provider": "mollie",
            },
        )
    )


class MollieOrderView:
    def dispatch(self, request, *args, **kwargs):
        try:
            self.order = request.event.orders.get(code=kwargs["order"])
            if (
                hashlib.sha1(self.order.secret.lower().encode()).hexdigest()
                != kwargs["hash"].lower()
            ):
                raise Http404("")
        except Order.DoesNotExist:
            # Do a hash comparison as well to harden timing attacks
            if (
                "abcdefghijklmnopq".lower()
                == hashlib.sha1("abcdefghijklmnopq".encode()).hexdigest()
            ):
                raise Http404("")
            else:
                raise Http404("")
        return super().dispatch(request, *args, **kwargs)

    @cached_property
    def payment(self):
        return get_object_or_404(
            self.order.payments,
            pk=self.kwargs["payment"],
            provider__startswith="mollie",
        )

    @cached_property
    def pprov(self):
        return self.payment.payment_provider


@method_decorator(xframe_options_exempt, "dispatch")
class ReturnView(MollieOrderView, View):
    def get(self, request, *args, **kwargs):
        if self.payment.state not in (
            OrderPayment.PAYMENT_STATE_CONFIRMED,
            OrderPayment.PAYMENT_STATE_FAILED,
            OrderPayment.PAYMENT_STATE_CANCELED,
        ):
            try:
                if self.payment.info_data.get("resource") == "order":
                    handle_order(self.payment, self.payment.info_data.get("id"))
                else:
                    handle_payment(self.payment, self.payment.info_data.get("id"))
            except LockTimeoutException:
                messages.error(
                    self.request,
                    _(
                        "We received your payment but were unable to mark your ticket as "
                        "the server was too busy. Please check back in a couple of "
                        "minutes."
                    ),
                )
            except Quota.QuotaExceededException:
                messages.error(
                    self.request,
                    _(
                        "We received your payment but were unable to mark your ticket as "
                        "paid as one of your ordered products is sold out. Please contact "
                        "the event organizer for further steps."
                    ),
                )
        return self._redirect_to_order()

    def _redirect_to_order(self):
        if self.request.session.get(
            "payment_mollie_order_secret"
        ) != self.order.secret and self.payment.provider not in (
            "mollie_ideal",
            "mollie_eps",
            "mollie_giropay",
        ):
            # We need to lift this requirement for payment methods that are known to open the redirect url in a browser
            # context of the banking app where our session does not exist. :(
            messages.error(
                self.request,
                _(
                    "Sorry, there was an error in the payment process. Please check the link "
                    "in your emails to continue."
                ),
            )
            return redirect(eventreverse(self.request.event, "presale:event.index"))

        return redirect(
            eventreverse(
                self.request.event,
                "presale:event.order",
                kwargs={"order": self.order.code, "secret": self.order.secret},
            )
            + ("?paid=yes" if self.order.status == Order.STATUS_PAID else "")
        )


@method_decorator(csrf_exempt, "dispatch")
class WebhookView(View):
    def post(self, request, *args, **kwargs):
        try:
            if request.POST.get("id") and request.POST["id"].startswith("ord_"):
                handle_order(self.payment, request.POST.get("id"))
            else:
                handle_payment(self.payment, request.POST.get("id"))
        except LockTimeoutException:
            return HttpResponse(status=503)
        except Quota.QuotaExceededException:
            pass
        return HttpResponse(status=200)

    @cached_property
    def payment(self):
        return get_object_or_404(
            OrderPayment.objects.filter(order__event=self.request.event),
            pk=self.kwargs["payment"],
            provider__startswith="mollie",
        )
