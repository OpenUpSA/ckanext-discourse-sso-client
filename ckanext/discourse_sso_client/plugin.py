# Based on https://github.com/ckan/ckanext-persona/blob/master/ckanext/persona/plugin.py

from ckan.common import config
from urllib import urlencode
from urlparse import parse_qs
import base64
import ckan.lib.helpers as helpers
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import hashlib
import hmac
import logging
import os
import pylons
import re


logger = logging.getLogger(__name__)


def get_sso_secret():
    return os.environ.get('CKAN_SSO_SECRET', config.get('sso.secret'))


def get_sso_url():
    return os.environ.get('CKAN_SSO_URL', config.get('sso.url'))


def get_sso_logout_url():
    return os.environ.get('CKAN_SSO_LOGOUT_URL', config.get('sso.logout_url'))


class SSOPlugin(plugins.SingletonPlugin):
    """Set up plugin for CKAN integration."""

    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IConfigurer)

    def update_config(self, config):
        '''Update CKAN's config with settings needed by this plugin.
        '''
        toolkit.add_template_directory(config, 'templates')
        toolkit.add_public_directory(config, 'public')
        toolkit.add_resource('fanstatic', 'persona')

    def login(self):
        """Login the user with credentials from the SocialAuth used. The CKAN
        username is created and access given.
        """
        logger.debug("\n\nLOGIN\n\n")

        params = toolkit.request.params

        if 'sso' in params and 'sig' in params:
            # Returns response as parse_qs dict on success, aborts on failure
            response = validate_response(params)

            # The SSO provider has securely identified someone for us.
            # Now get or create the user.

            email = response['email'][0]
            user = get_user(email)
            if not user:
                # A user with this email address doesn't yet exist in CKAN,
                # so create one.
                logger.debug("Creating user from SSO response %r", response)
                user_dict = {
                    'email': email,
                    'name': generate_username(response['username'][0]),
                    'password': generate_password(),
                    'fullname': response['name'][0],
                }

                user = toolkit.get_action('user_create')(
                    context={'ignore_auth': True},
                    data_dict=user_dict)

            pylons.session['ckanext-discourse-sso-client-user'] = user['name']
            pylons.session.save()
            self.identify()

            came_from = pylons.session.get('ckanext-discourse-sso-client-came_from', '')
            helpers.redirect_to(controller='user', action='logged_in', came_from=came_from)

        else:
            pylons.session['ckanext-discourse-sso-client-came_from'] = params.get('came_from', '')
            start_sso()

    def identify(self):
        '''Identify which user (if any) is logged-in via Persona.
        If a logged-in user is found, set toolkit.c.user to be their user name.
        '''
        logger.debug("\n\nIDENTIFY\n\n")

        # Try to get the item that login() placed in the session.
        user = pylons.session.get('ckanext-discourse-sso-client-user')
        if user:
            # We've found a logged-in user. Set c.user to let CKAN know.
            toolkit.c.user = user
        else:
            logger.debug("No user in session")

    def _delete_session_items(self):
        if 'ckanext-discourse-sso-client-user' in pylons.session:
            del pylons.session['ckanext-discourse-sso-client-user']
        if 'ckanext-discourse-sso-client-came_from' in pylons.session:
            del pylons.session['ckanext-discourse-sso-client-came_from']
        if 'ckanext-discourse-sso-client-nonce' in pylons.session:
            del pylons.session['ckanext-discourse-sso-client-nonce']
        pylons.session.save()

    def logout(self):
        '''Handle a logout.'''

        # Delete the session item, so that identify() will no longer find it.
        self._delete_session_items()

    def abort(self, status_code, detail, headers, comment):
        '''Handle an abort.'''

        # Delete the session item, so that identify() will no longer find it.
        self._delete_session_items()


def start_sso():
    nonce = os.urandom(24).encode('hex')
    raw_payload = urlencode({'nonce': nonce})
    payload = base64.encodestring(raw_payload)
    sig = sign(payload)
    qs = urlencode({'sso': payload, 'sig': sig})
    sso_url = "%s?%s" % (get_sso_url(), qs)

    pylons.session['ckanext-discourse-sso-client-nonce'] = nonce
    pylons.session.save()
    toolkit.redirect_to(sso_url)


def validate_response(params):
    """
    Checks that
    - the signature is valid for the payload
    - the nonce is the same one used to initiate the login
    Deletes a valid nonce to avoid replay.
    DOES NOT save session - expects caller to do so
    """
    payload = params['sso']
    sig = unicode(sign(payload))
    if not hmac.compare_digest(sig, params['sig']):
        logger.debug("Invalid signature")
        toolkit.abort(401)
    raw_payload = base64.decodestring(payload)
    response = parse_qs(raw_payload, keep_blank_values=True)
    nonce = pylons.session['ckanext-discourse-sso-client-nonce']
    if not hmac.compare_digest(nonce, response['nonce'][0]):
        toolkit.abort(401)
        logger.debug("Invalid nonce")
    # Delete validated nonce to avoid replay
    del pylons.session['ckanext-discourse-sso-client-nonce']
    return response


def sign(payload):
    key = get_sso_secret()
    return hmac.new(key, payload, digestmod=hashlib.sha256).hexdigest()


def get_user(email):
    '''Return the CKAN user with the given email address.
    :rtype: A CKAN user dict
    '''
    # We do this by accessing the CKAN model directly, because there isn't a
    # way to search for users by email address using the API yet.
    import ckan.model
    users = ckan.model.User.by_email(email)

    assert len(users) in (0, 1), ("The Discourse-SSO-Client plugin doesn't know"
                                  " what to do when CKAN has more than one user"
                                  " with the same email address.")

    if users:

        # But we need to actually return a user dict, so we need to convert it
        # here.
        user = users[0]
        user_dict = toolkit.get_action('user_show')(data_dict={'id': user.id})
        return user_dict

    else:
        return None


def generate_username(username):
    '''Generate a random user name for the given email address.
    '''
    username = re.sub('\W+', '_', username)
    return str(username)


def generate_password():
    '''Generate a random password.
    '''
    return os.urandom(24).encode('hex')
