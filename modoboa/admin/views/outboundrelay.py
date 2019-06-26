# -*- coding: utf-8 -*-

"""Domain related views."""

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
#from ..forms import DomainForm, DomainWizard
from ..lib import get_outboundrelays
from ..models import Domain, Mailbox


@login_required
@user_passes_test(
    lambda u: u.has_perm("admin.view_domains") or
    u.has_perm("admin.view_mailboxes")
)
def _outboundrelays(request):
    sort_order, sort_dir = get_sort_order(request.GET, "name")
    extra_filters = signals.extra_domain_filters.send(sender="_domains")
    if extra_filters:
        extra_filters = reduce(
            lambda a, b: a + b, [result[1] for result in extra_filters])
    filters = {
        flt: request.GET.get(flt, None)
        for flt in ["domfilter", "searchquery"] + extra_filters
    }
    request.session["domains_filters"] = filters
    domainlist = get_domains(request.user, **filters)
    if sort_order == "name":
        domainlist = sorted(
            domainlist,
            key=lambda d: getattr(d, sort_order), reverse=sort_dir == "-"
        )
    else:
        domainlist = sorted(domainlist, key=lambda d: d.tags[0]["name"],
                            reverse=sort_dir == "-")
    context = {
        "handle_mailboxes": request.localconfig.parameters.get_value(
            "handle_mailboxes", raise_exception=False),
        "auto_account_removal": request.localconfig.parameters.get_value(
            "auto_account_removal"),
    }
    page = get_listing_page(domainlist, request.GET.get("page", 1))
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
        "admin/domain_headers.html", dns_checks, request
    )
    if page is None:
        context["length"] = 0
    else:
        tpl_context = {"domains": page.object_list}
        tpl_context.update(dns_checks)
        context["rows"] = render_to_string(
            "admin/domains_table.html", tpl_context, request
        )
        context["pages"] = [page.number]
    return render_to_json_response(context)


@login_required
@ensure_csrf_cookie
def outboundrelays(request, tplname="admin/domains.html"):
    if not request.user.has_perm("admin.view_domains"):
        if request.user.has_perm("admin.view_mailboxes"):
            return HttpResponseRedirect(
                reverse("admin:identity_list")
            )
        return HttpResponseRedirect(reverse("core:user_index"))
    parameters = request.localconfig.parameters
    return render(request, tplname, {
        "selection": "domains",
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
    doms = [dom.name for dom in Domain.objects.get_for_admin(request.user)]
    return render_to_json_response(doms)

