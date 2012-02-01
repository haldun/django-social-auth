"""
Turkcell OpenID support

No extra configurations are needed to make this work.
"""
import logging
logger = logging.getLogger(__name__)

from openid.extensions import sreg

from social_auth.backends import OpenIDBackend, OpenIdAuth
from social_auth.store import DjangoOpenIDStore

TURKCELL_OPENID_URL = 'http://turkcellid.turkcell.com.tr/x'

# Attributes that we map from a variable SReg.fromSuccessResponse
TURKCELL_ATTRS = [
    ('email', 'sreg.email'),
    ('fullname', 'sreg.fullname'),
    ('nickname', 'sreg.nickname')
]

class TurkcellBackend(OpenIDBackend):
    """Turkcell OpenID authentication backend"""
    name = 'turkcell'

    def values_from_response(self, response, sreg_names):
        """Return values from SimpleRegistration response

        The code is a modified version of what's in OpenIDBackend

        Turkcell only supportes SReg so we will not check for
        ax response.

        @sreg_names be a list of name and aliases
        for such name. The alias will be used as mapping key.
        """
        values = {}

        resp = sreg.SRegResponse.fromSuccessResponse(response, False)

        ############################################################################
        # Turkcell provides related fields with sreg. prefix. If we got it,        #
        # map these sreg fields to normal values that will be used by Django auth. #
        ############################################################################

        if resp:
            values.update((name, resp.get(alias) or '')
                                for name, alias in sreg_names)
        else:
            print "### DEBUG: Unexpected case. sreg.SregResponse.fromSuccessResponse should not return None"

        return values

    def get_user_details(self, response):
        """Return user details from an OpenID request

        This is a modified version of what's in OpenIDBackend.

        Turkcell does not support AX Schema, so we will only get
        SReg.

        """

        values = {"username": '', 'email': '', 'fullname': '',
                  'first_name': '', 'last_name': ''}

        # update values using SimpleRegistration
        values.update(self.values_from_response(response, TURKCELL_ATTRS))
        fullname = values.get('fullname') or ''
        first_name = values.get('first_name') or ''
        last_name = values.get('last_name') or ''

        if not fullname and first_name and last_name:
            fullname = first_name + ' ' + last_name
        elif fullname:
            try:  # Try to split name for django user storage
                first_name, last_name = fullname.rsplit(' ', 1)
            except ValueError:
                last_name = fullname

        values.update({'fullname': fullname, 'first_name': first_name,
                       'last_name': last_name,
                       'username': values.get('nickname')})
        return values

    def extra_data(self, user, uid, response, details):
        """Return default blank user extra data"""
        return ''


class TurkcellAuth(OpenIdAuth):
    """Turkcell OpenID authentication"""
    AUTH_BACKEND = TurkcellBackend

    def openid_url(self):
        """Return Turkcell OpenID service url"""
        return TURKCELL_OPENID_URL

# Backend definition
BACKENDS = {
    'turkcell': TurkcellAuth,
}
