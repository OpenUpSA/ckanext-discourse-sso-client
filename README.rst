============================
ckanext-discourse-sso-client
============================

.. This extension allows a user to login to CKAN using an account in another
   system which provides the Discourse SSO provider service. It implements the
   Discourse-side of the interaction.

https://meta.discourse.org/t/official-single-sign-on-for-discourse-sso/13045

It assumes email addresses are unique, and logs the user in as the email address
returned by the SSO provider. If the user does not exist, they are created.


------------
Requirements
------------

This extension is tested with CKAN v.2.7.2

------------
Installation
------------

.. Add any additional install steps to the list below.
   For example installing any non-Python dependencies or adding any required
   config settings.

To install ckanext-discourse-sso-client:

1. Activate your CKAN virtual environment, for example::

     . /usr/lib/ckan/default/bin/activate

2. Install the ckanext-discourse-sso-client Python package into your virtual environment::

     pip install git+https://github.com/OpenUpSA/ckanext-discourse-sso-client.git

3. Add ``discourse-sso-client`` to the ``ckan.plugins`` setting in your CKAN
   config file (by default the config file is located at
   ``/etc/ckan/default/production.ini``).

4. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu::

     sudo service apache2 reload


---------------
Config Settings
---------------

sso.url or environment variable CKAN_SSO_URL e.g. http://localhost:8000/ckan/sso

sso.secret or evironment variable CKAN_SSO_SECRET


------------------------
Development Installation
------------------------

To install ckanext-discourse-sso-client for development, activate your CKAN virtualenv and
do::

    git clone https://github.com/OpenUpSA/ckanext-discourse-sso-client.git
    cd ckanext-discourse-sso-client
    python setup.py develop
    pip install -r dev-requirements.txt

-------
LICENSE
-------

MIT License
