# Generated by Django 4.2.15 on 2025-01-31 12:42

from django.db import migrations
from django_scopes import scopes_disabled

from pretix.base.models import OrderPayment, OrderRefund


@scopes_disabled()
def migrate_applepay(apps, schema_editor):
    OrderPayment.objects.filter(provider="mollie_applepay").update(
        provider="mollie_creditcard",
    )

    OrderRefund.objects.filter(provider="mollie_applepay").update(
        provider="mollie_creditcard",
    )

class Migration(migrations.Migration):

    dependencies = []

    operations = [
        migrations.RunPython(migrate_applepay, migrations.RunPython.noop)
    ]
