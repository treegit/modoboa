# -*- coding: utf-8 -*-

"""Outbound relay related views."""

from __future__ import unicode_literals

from functools import reduce

from reversion import revisions as reversion

from django.contrib.auth import mixins as auth_mixins
from django.contrib.auth.decorators import (
    login_required, permission_required, user_passes_test
)
from django.db.models import Sum
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.translation import ugettext as _, ungettext
from django.views import generic
from django.views.decorators.csrf import ensure_csrf_cookie

from modoboa.core import signals as core_signals
from modoboa.lib.exceptions import PermDeniedException
from modoboa.lib.listing import get_listing_page, get_sort_order
from modoboa.lib.web_utils import render_to_json_response
from .. import signals
from ..forms import OutboundRelayForm
from ..lib import get_outboundrelays
from ..models import OutboundRelay


@login_required
@user_passes_test(
    lambda u: u.has_perm("admin.view_outboundrelays")
)
def _outboundrelays(request):
    sort_order, sort_dir = get_sort_order(request.GET, "name")
    extra_filters = signals.extra_outboundrelay_filters.send(sender="_outboundrelays")
    if extra_filters:
        extra_filters = reduce(
            lambda a, b: a + b, [result[1] for result in extra_filters])
    filters = {
        flt: request.GET.get(flt, None)
        for flt in ["relayfilter", "searchquery"] + extra_filters
    }
    request.session["outboundrelays_filters"] = filters
    relaylist = get_outboundrelays(request.user, **filters)
    if sort_order == "name":
        relaylist = sorted(
            relaylist,
            key=lambda d: getattr(d, sort_order), reverse=sort_dir == "-"
        )
    else:
        relaylist = sorted(relaylist, key=lambda d: d.tags[0]["name"],
                            reverse=sort_dir == "-")
    context = {
        "handle_mailboxes": request.localconfig.parameters.get_value(
            "handle_mailboxes", raise_exception=False),
        "auto_account_removal": request.localconfig.parameters.get_value(
            "auto_account_removal"),
    }
    page = get_listing_page(relaylist, request.GET.get("page", 1))
    parameters = request.localconfig.parameters
    dns_checks = {
        "enable_mx_checks": parameters.get_value("enable_mx_checks"),
        "enable_spf_checks": parameters.get_value("enable_spf_checks"),
        "enable_dkim_checks": parameters.get_value("enable_dkim_checks"),
        "enable_dmarc_checks": parameters.get_value("enable_dmarc_checks"),
        "enable_autoconfig_checks": (
            parameters.get_value("enable_autoconfig_checks")),
        "enable_dnsbl_checks": parameters.get_value("enable_dnsbl_checks")
    }
    context["headers"] = render_to_string(
        "admin/outboundrelay_headers.html", dns_checks, request
    )
    if page is None:
        context["length"] = 0
    else:
        tpl_context = {"relays": page.object_list}
        tpl_context.update(dns_checks)
        context["rows"] = render_to_string(
            "admin/outboundrelays_table.html", tpl_context, request
        )
        context["pages"] = [page.number]
    return render_to_json_response(context)


@login_required
@ensure_csrf_cookie
def outboundrelays(request, tplname="admin/outboundrelays.html"):
    if not request.user.has_perm("admin.view_outboundrelays"):
        return HttpResponseRedirect(reverse("core:user_index"))
    parameters = request.localconfig.parameters
    return render(request, tplname, {
        "selection": "outboundrelays",
        "enable_mx_checks": parameters.get_value("enable_mx_checks"),
        "enable_spf_checks": parameters.get_value("enable_spf_checks"),
        "enable_dkim_checks": parameters.get_value("enable_dkim_checks"),
        "enable_dmarc_checks": parameters.get_value("enable_dmarc_checks"),
        "enable_autoconfig_checks": (
            parameters.get_value("enable_autoconfig_checks")),
        "enable_dnsbl_checks": parameters.get_value("enable_dnsbl_checks")
    })


@login_required
@permission_required("core.add_user")
def outboundrelays_list(request):
    relays = [relay.name for relay in OutboundRelay.objects.get_for_admin(request.user)]
    return render_to_json_response(relays)

@login_required
@permission_required("admin.add_outboundrelay")
@reversion.create_revision()
def newoutboundrelay(request):
    core_signals.can_create_object.send(
        "newoutboundrelay", context=request.user, klass=OutboundRelay)
    return _new_outboundrelay(
        request, _("New outbound relay"), reverse("admin:outboundrelay_add"),
        _("Outbound relay created")
    )


def _validate_outboundrelay(request, form, successmsg, callback=None):
    """Alias validation

    Common function shared between creation and modification actions.
    """
    if form.is_valid():
        try:
            relay = form.save()
        except IntegrityError:
            raise Conflict(_("Outbound relay with this name already exists"))
        if callback:
            callback(request.user, alias)
        return render_to_json_response(successmsg)

    return render_to_json_response({"form_errors": form.errors}, status=400)


def _new_outboundrelay(request, title, action, successmsg,
               tplname="admin/outboundrelayform.html"):
    core_signals.can_create_object.send(
        "new_outboundrelay", context=request.user, klass=OutboundRelay)
    if request.method == "POST":
        def callback(user, alias):
            alias.post_create(user)

        form = OutboundRelayForm(request.user, request.POST)
        return _validate_outboundrelay(
            request, form, successmsg, callback
        )

    ctx = {
        "title": title,
        "action": action,
        "formid": "outboundrelayform",
        "action_label": _("Create"),
        "action_classes": "submit",
        "form": OutboundRelayForm(request.user)
    }
    return render(request, tplname, ctx)

