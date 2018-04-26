import pprint
import ssl
import sys
import xmlrpclib
import logging

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for EUserv
    This Authenticator uses the EUserv API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using EUserv for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='EUserv credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the EUserv API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'EUserv credentials INI file',
            {
                'username': 'username for EUserv Reseller API account',
                'password': 'password for EUserv Reseller API account'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_euserv_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_euserv_client().del_txt_record(domain, validation_name, validation)

    def _get_euserv_client(self):
        return _EUservClient(self.credentials.conf('username'), self.credentials.conf('password'))


class _EUservClient(object):
    """
    Encapsulates all communication with the EUserv API.
    """

    def __init__(self, username, password):
        self.auth = dict(login=username, password=password)
        self.rpc = xmlrpclib.ServerProxy('https://api.euserv.net',
            # what a shame but they really use an self-signed cert
            context = ssl._create_unverified_context())

    def add_txt_record(self, domain_name, record_name, record_content):
        """
        Add a TXT record using the supplied information.
        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the EUserv
                                            API
        """

        try:
            domain = self._find_domain(domain_name)
        except (xmlrpclib.ProtocolError, xmlrpclib.Fault) as e:
            hint = None

            if 'Authentication failed' in str(e):
                hint = 'Did you provide a valid username/password combination?'

            logger.debug('Error finding domain using the EUserv API: %s', e)
            raise errors.PluginError('Error finding domain using the EUserv API: {0}{1}'
                                     .format(e, ' ({0})'.format(hint) if hint else ''))

        try:
            result = self.rpc.domain.dns_create_record(dict(self.auth,
                domain_id=domain['domain_id'],
                dns_record_subdomain=record_name.rpartition('.' + domain['domain_name'])[0],
                dns_record_type='TXT',
                dns_record_value=record_content,
                dns_record_ttl=43200
            ))

            if result['status'] == 100:
                logger.debug('Successfully added TXT record with id: %d', result['dns_record_id'])
            else:
                raise RuntimeError(result)
        except (xmlrpclib.ProtocolError, xmlrpclib.Fault, RuntimeError) as e:
            logger.debug('Error adding TXT record using the EUserv API: %s', e)
            raise errors.PluginError('Error adding TXT record using the EUserv API: {0}'
                                     .format(e))

    def del_txt_record(self, domain_name, record_name, record_content):
        """
        Delete a TXT record using the supplied information.
        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.
        Failures are logged, but not raised.
        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        try:
            domain = self._find_domain(domain_name)
        except (xmlrpclib.ProtocolError, xmlrpclib.Fault) as e:
            logger.debug('Error finding domain using the EUserv API: %s', e)
            return
        try:
            domain_records = self.rpc.domain.dns_get_active_records(dict(self.auth, domain_id=domain['domain_id']))['dns_records']
            matching_record_ids = [int(record_id) for record_id, record in domain_records.iteritems()
                                if record['dns_record_type'] == 'TXT'
                                and record['dns_record_name'] == record_name
                                and record['dns_record_content'] == record_content]
        except (xmlrpclib.ProtocolError, xmlrpclib.Fault) as e:
            logger.debug('Error getting DNS records using the EUserv API: %s', e)
            return

        for record_id in matching_record_ids:
            try:
                logger.debug('Removing TXT record with id: %s', record_id)
                self.rpc.domain.dns_delete_record(dict(self.auth, dns_record_id=record_id))
            except (xmlrpclib.ProtocolError, xmlrpclib.Fault) as e:
                logger.warn('Error deleting TXT record %s using the EUserv API: %s',
                            record_id, e)

    def _find_domain(self, domain_name):
        """
        Find the domain object for a given domain name.
        :param str domain_name: The domain name for which to find the corresponding domain_id.
        :returns: object with 'domain_name' and 'domain_id'
        :raises certbot.errors.PluginError: if no matching Domain is found.
        """
        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)
        domains = self.rpc.domain.get_domain_orders(self.auth)['domain_orders'].values()

        for guess in domain_name_guesses:
            matches = [domain for domain in domains if domain['domain_name'] == guess]

            if len(matches) > 0:
                domain = matches[0]
                logger.debug('Found base domain for %s using name %s', domain_name, guess)
                return domain

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
                                 .format(domain_name, domain_name_guesses))
