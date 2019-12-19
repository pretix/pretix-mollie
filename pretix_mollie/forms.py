from django import forms
from django.utils.translation import ugettext_lazy as _

from pretix.base.forms import SettingsForm


class MollieKeyValidator:
    def __init__(self, prefix):
        assert len(prefix) > 0
        if isinstance(prefix, list):
            self._prefixes = prefix
        else:
            self._prefixes = [prefix]
            assert isinstance(prefix, str)

    def __call__(self, value):
        if not any(value.startswith(p) for p in self._prefixes):
            raise forms.ValidationError(
                _('The provided key "%(value)s" does not look valid. It should start with "%(prefix)s".'),
                code='invalid-mollie-key',
                params={
                    'value': value,
                    'prefix': self._prefixes[0],
                },
            )


class OrganizerMollieSettingsForm(SettingsForm):
    mollie_api_key = forms.CharField(
        label=_('Mollie API key'),
        help_text=_("Organizer wide mollie API key. Will overwrite all event API-keys and "
                    "make the API key inaccessable for non administrators."),
        validators=(
            MollieKeyValidator(['live_', 'test_']),
        ),
        required=False,
    )

    mollie_allow_method_creditcard = forms.BooleanField(
        label=_('Credit card'),
        required=False,
    )
    mollie_allow_method_bancontact = forms.BooleanField(
        label=_('Bancontact'),
        required=False,
    )
    mollie_allow_method_banktransfer = forms.BooleanField(
        label=_('Bank transfer'),
        required=False,
    )
    mollie_allow_method_belfius = forms.BooleanField(
        label=_('Belfius Pay Button'),
        required=False,
    )
    mollie_allow_method_bitcoin = forms.BooleanField(
        label=_('Bitcoin'),
        required=False,
    )
    mollie_allow_method_eps = forms.BooleanField(
        label=_('EPS'),
        required=False,
    )
    mollie_allow_method_giropay = forms.BooleanField(
        label=_('giropay'),
        required=False,
    )
    mollie_allow_method_ideal = forms.BooleanField(
        label=_('iDEAL'),
        required=False,
    )
    mollie_allow_method_inghomepay = forms.BooleanField(
        label=_('ING Home’Pay'),
        required=False,
    )
    mollie_allow_method_kbc = forms.BooleanField(
        label=_('KBC/CBC Payment Button'),
        required=False,
    )
    mollie_allow_method_paysafecard = forms.BooleanField(
        label=_('paysafecard'),
        required=False,
    )
    mollie_allow_method_sofort = forms.BooleanField(
        label=_('Sofort'),
        required=False,
    )
