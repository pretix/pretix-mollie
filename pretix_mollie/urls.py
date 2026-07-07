from django.urls import include, path, re_path
from pretix.multidomain import event_path, event_url

from .views import (
    ReturnView, Webhook2View, oauth_disconnect, oauth_return, redirect_view,
)

event_patterns = [
    path(
        "mollie/",
        include(
            [
                event_path(
                    "webhook2/<str:order>/<str:hash>/<int:payment>/",
                    Webhook2View.as_view(),
                    name="webhook2",
                    require_live=False,
                ),
                path("redirect/", redirect_view, name="redirect"),
                path(
                    "return/<str:order>/<str:hash>/<int:payment>/",
                    ReturnView.as_view(),
                    name="return",
                ),
            ]
        ),
    ),
]

urlpatterns = [
    re_path(
        r"^control/event/(?P<organizer>[^/]+)/(?P<event>[^/]+)/mollie/disconnect/",
        oauth_disconnect,
        name="oauth.disconnect",
    ),
    path("_mollie/oauth_return/", oauth_return, name="oauth.return"),
]
