# -*- coding: utf-8 -*-

"""Forms related to OutboundRelays management."""

from __future__ import unicode_literals

from functools import reduce

from django import forms
from django.http import QueryDict
from django.urls import reverse
from django.utils.encoding import force_text
from django.utils.translation import ugettext as _, ugettext_lazy

from modoboa.core import signals as core_signals
from modoboa.core.models import User
from modoboa.lib.exceptions import Conflict
from modoboa.lib.fields import DomainNameField
from modoboa.lib.form_utils import (
    DynamicForm, TabForms, WizardForm, WizardStep, YesNoField
)
from modoboa.lib.web_utils import render_to_json_response, size2integer
from modoboa.parameters import tools as param_tools
from .. import constants, lib, signals
from ..models import Alias, Domain, DomainAlias, Mailbox
from ..models import OutboundRelay


class OutboundRelayForm(forms.ModelForm, DynamicForm):
    """A form to create/edit a OutboundRelay."""

    class Meta:
        model = OutboundRelay
        fields = (
            "name", "relayhost", "is_default_for_all_senders", "use_tls", "tls_cafile",
            "auth_required", "username", "password",
            "client_cert"
        )

    def __init__(self, user, *args, **kwargs):
        self.oldname = None
        if "instance" in kwargs:
            self.old_dkim_key_length = kwargs["instance"].dkim_key_length
            self.oldname = kwargs["instance"].name
        super(OutboundRelayForm, self).__init__(*args, **kwargs)
        params = dict(param_tools.get_global_parameters("admin"))
        self.user = user

        if len(args) and isinstance(args[0], QueryDict):
            self._load_from_qdict(args[0], "aliases", DomainNameField)
        elif "instance" in kwargs:
            d = kwargs["instance"]
            for pos, dalias in enumerate(d.domainalias_set.all()):
                name = "aliases_%d" % (pos + 1)
                self._create_field(forms.CharField, name, dalias.name, 3)
