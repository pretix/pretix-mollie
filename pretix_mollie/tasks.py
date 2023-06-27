from django_scopes import scopes_disabled

from pretix.base.models import OrderPayment
from pretix.celery_app import app


@app.task()
@scopes_disabled()
def extend_payment_deadline(payment):
    payment = OrderPayment.objects.get(pk=payment)
    pprov = payment.payment_provider

    pprov.update_payment_due(payment)
