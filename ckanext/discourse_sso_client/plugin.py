# Based on https://github.com/ckan/ckanext-persona/blob/master/ckanext/persona/plugin.py

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.lib.helpers as helpers
import logging
import pylons
from ckan.common import config
import os

logger = logging.getLogger(__name__)


def get_sso_secret():
    return os.environ.get('CKAN_SSO_SECRET', config.get('sso.secret'))


def get_sso_url():
    return os.environ.get('CKAN_SSO_URL', config.get('sso.url'))


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
        logger.info("\n\nLOGIN\n\n")
        toolkit.redirect_to(get_sso_url())

    def identify(self):
        '''Identify which user (if any) is logged-in via Persona.
        If a logged-in user is found, set toolkit.c.user to be their user name.
        '''
        logger.info("\n\nIDENTIFY\n\n")

        # Try to get the item that login() placed in the session.
        user = pylons.session.get('ckanext-persona-user')
        if user:
            # We've found a logged-in user. Set c.user to let CKAN know.
            toolkit.c.user = user

    def _delete_session_items(self):
        import pylons
        if 'ckanext-persona-user' in pylons.session:
            del pylons.session['ckanext-persona-user']
        if 'ckanext-persona-email' in pylons.session:
            del pylons.session['ckanext-persona-email']
        pylons.session.save()

    def logout(self):
        '''Handle a logout.'''

        # Delete the session item, so that identify() will no longer find it.
        self._delete_session_items()

    def abort(self, status_code, detail, headers, comment):
        '''Handle an abort.'''

        # Delete the session item, so that identify() will no longer find it.
        self._delete_session_items()


def get_user(email):
    '''Return the CKAN user with the given email address.
    :rtype: A CKAN user dict
    '''
    # We do this by accessing the CKAN model directly, because there isn't a
    # way to search for users by email address using the API yet.
    import ckan.model
    users = ckan.model.User.by_email(email)

    assert len(users) in (0, 1), ("The Persona plugin doesn't know what to do "
                                  "when CKAN has more than one user with the "
                                  "same email address.")

    if users:

        # But we need to actually return a user dict, so we need to convert it
        # here.
        user = users[0]
        user_dict = toolkit.get_action('user_show')(data_dict={'id': user.id})
        return user_dict

    else:
        return None


def generate_password():
    '''Generate a random password.
    '''
    return os.urandom(24).encode('hex')
