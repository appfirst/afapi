# encoding: utf-8

"""
Uses V4 of AppFirst's HTTP API

Full API documentation: http://support.appfirst.com/apis/
"""

__author__ = "Michael Okner"
__copyright__ = "Copyright 2014, AppFirst, Inc."
__credits__ = ["Michael Okner"]
__license__ = "Apache2"  # TODO
__version__ = "1.0"
__maintainer__ = "Michael Okner"
__email__ = "michael@appfirst.com"
__status__ = "Development"


try:
    import simplejson as json
except ImportError:
    import json

from . import requests
from . import exceptions


class AppFirstApi(object):
    """
    An object for connecting/authenticating with AppFirst APIs and retrieving
    different forms of data.
    """

    def __init__(self, email=None, api_key=None, base_url='https://wwws.appfirst.com/api'):
        self.email = email
        self.api_key = api_key
        self.base_url = base_url


    # Helper methods
    def _make_api_request(self, url, **kwargs):
        """
        Hits the API at `url` and returns the data from the request

        kwargs can be:
            - method:  defaults to 'GET'
            - params:  defaults to {}
            - data:    defaults to '' (for PUT requests)
            - headers: defaults to {}
        """
        full_url = self.base_url + url
        method = kwargs.get('method', 'GET')
        params = kwargs.get('params', {})
        headers = kwargs.get('headers', {})
        data = kwargs.get('data', '')
        if isinstance(data, dict):
            data = json.dumps(data)

        if method == 'GET':
            request_method = requests.get
        elif method == 'POST':
            request_method = requests.post
        elif method == 'PUT':
            request_method = requests.put
        elif method == 'DELETE':
            request_method = requests.delete
        else:
            raise ValueError("Invalid HTTP method: {0}".format(method))

        # Make request and check return status
        r = request_method(full_url, auth=(self.email, self.api_key),
                           params=params, data=data, headers=headers)
        if r.status_code == requests.codes.ok:
            return r.json()
        else:
            raise exceptions.RequestError("Server returned status code: {0}".format(r.status_code))


    # Server APIs
    def get_servers(self, hostname=None):
        """
        Lists all available servers.

        http://support.appfirst.com/apis/servers/#servers
        """
        params = {'hostname': hostname} if hostname else {}
        return self._make_api_request('/servers/', params=params)


    def get_server(self, host_id):
        """
        View a server.

        http://support.appfirst.com/apis/servers/#serverid
        """
        return self._make_api_request('/servers/{0}/'.format(host_id))


    def update_server(self, host_id, data):
        """
        Edit a server. Data argument should look like 'nickname=new_nick'

        http://support.appfirst.com/apis/servers/#serverid
        """
        # Sanity checks
        if not isinstance(data, str):
            raise TypeError("Data must be a string")
        if '=' not in data:
            raise ValueError("Invalid data string format")

        return self._make_api_request('/servers/{0}/'.format(host_id), data=data)


    def delete_server(self, host_id):
        """
        Delete a server.

        http://support.appfirst.com/apis/servers/#serverid
        """
        return self._make_api_request('/servers/{0}/'.format(host_id), method='DELETE')


    def get_server_data(self, host_id, limit=5):
        """
        Retrieves data for the given server.

        http://support.appfirst.com/apis/servers/#serveriddata
        """
        return NotImplemented


    def get_server_outages(self, host_id):
        """
        This API lists the recent outages for the given server.

        http://support.appfirst.com/apis/servers/#serveridoutages
        """
        return NotImplemented


    def get_polled_data_config(self, host_id):
        """
        Get the Polled Data config on a server.

        http://support.appfirst.com/apis/servers/#serveridpolleddata
        """
        return NotImplemented


    def update_polled_data_config(self, host_id):
        """
        Update the Polled Data config on a server.

        http://support.appfirst.com/apis/servers/#serveridpolleddata
        """
        return NotImplemented


    def get_server_tags(self, host_id):
        """
        Retrieves the server tag information for a particular server.

        http://support.appfirst.com/apis/servers/#serveridtags
        """
        return NotImplemented


    def update_server_tags(self, host_id):
        """
        Updates the server tags that this server belongs to.

        http://support.appfirst.com/apis/servers/#serveridtags
        """
        return NotImplemented


    def trigger_server_app_auto_detect(self, host_id):
        """
        Trigger auto application detection on this server. The result is a list
        application name that detected on this server.

        http://support.appfirst.com/apis/servers/#serveridautodetection
        """
        return NotImplemented


    # Process APIs
    def get_processes(self, host_id):
        """
        Returns the list of processes on a server. See the Processes API
        documentation for more information about process objects.

        http://support.appfirst.com/apis/servers/#serveridprocesses
        """
        return NotImplemented


    def get_processes_data(self, host_id):
        """
        Returns the list of a processes’ summary data on a particular server.

        http://support.appfirst.com/apis/servers/#serveridprocessesdata
        """
        return NotImplemented
