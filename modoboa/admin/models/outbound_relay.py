# -*- coding: utf-8 -*-

"""Relay domain related models."""

from __future__ import unicode_literals

from reversion import revisions as reversion

from django.db import models
from django.utils.encoding import (
    force_text, python_2_unicode_compatible, smart_text
)

from django.utils.translation import ugettext_lazy

from modoboa.core import signals as core_signals
from modoboa.core.models import User
from modoboa.lib.exceptions import BadRequest, Conflict
from modoboa.lib import cryptutils
from modoboa.parameters import tools as param_tools

from .. import constants
from .base import AdminObject


@python_2_unicode_compatible
class OutboundRelay(AdminObject):
    """An recipient level access table."""

    name = models.CharField(ugettext_lazy("name"), max_length=100, unique=True,
                            help_text=ugettext_lazy("A unique name to identify this relayhost/auth combination"))
    relayhost = models.CharField(db_index=True, max_length=254)
    is_default_for_all_senders = models.BooleanField(
        ugettext_lazy("is default for all senders"),
        help_text=ugettext_lazy("Check to activate this domain"),
        default=True
    )
    use_tls = models.BooleanField(
        ugettext_lazy("use_tls"),
        help_text=ugettext_lazy("Check to make this connection use tls"),
        default=True
    )
    tls_cafile = models.CharField(max_length=254)
    auth_required = models.BooleanField(
        ugettext_lazy("Authentication is required"),
        help_text=ugettext_lazy("Check to make this connection always use authentication"),
        default=True
    )
    username = models.CharField(max_length=254)
    password = models.CharField(ugettext_lazy("password"), max_length=512)
    client_cert = models.CharField(ugettext_lazy("client certificate"), max_length=512)

    class Meta:
        permissions = (
            ("view_outboundrelay", "View outbound relay"),
            ("view_outboundrelays", "View outbound relay"),
        )
        ordering = ["name"]
        app_label = "admin"

    def set_password(self, raw_value):
        """Password update

        Update the password for this relayhost
        This value is encrypted using Fernet and the same key as all else

        :param raw_value: the new password's value
        """
        if raw_value == '':
            self.password = ''
        else:
            self.password = cryptutils.encrypt(raw_value)
        signals.account_password_updated.send(
            sender=self.__class__,
            account=self, password=raw_value, created=self.pk is None)

    def get_decrypted_password(self, raw_value):
        """Password update

        Update the password for this relayhost
        This value is encrypted using Fernet and the same key as all else

        :param raw_value: the new password's value
        """
        password = ''
        if self.password != '':
            password = cryptutils.decrypt(self.password)
        return password

reversion.register(OutboundRelay)
