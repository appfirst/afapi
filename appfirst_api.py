# encoding: utf-8

"""
Uses V4 of AppFirst's HTTP API

Full API documentation: http://support.appfirst.com/apis/
"""


import time
import datetime
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
        Edit a server. Data argument should be a dict like {'nickname': 'new_nick'}

        http://support.appfirst.com/apis/servers/#serverid
        """
        if not isinstance(data, dict):
            raise TypeError("Data must be a dictionary")

        return self._make_api_request('/servers/{0}/'.format(host_id), data=data)


    def delete_server(self, host_id):
        """
        Delete a server.

        http://support.appfirst.com/apis/servers/#serverid
        """
        return self._make_api_request('/servers/{0}/'.format(host_id), method='DELETE')


    def get_server_data(self, host_id, **kwargs):
        """
        Retrieves data for the given server.

        Arguments:
            - host_id: required, first arg, non-keyword.
            - num: optional keyword, max number of data points to retrieve. Defaults to one.
            - end: optional keyword, retrieves data from this datetime object backwards. Defaults to current time.
            - start: optional keyword, won't retrieve data from before this datetime object.
            - time_step: optional keyword, time step for the data. Can be 'Minute', 'Hour', 'Day'. Default is 'Minute'.

        http://support.appfirst.com/apis/servers/#serveriddata
        """
        params = {'num': kwargs.get('num', 1)}
        end = kwargs.get('end', None)
        start = kwargs.get('start', None)
        time_step = kwargs.get('time_step', 'Minute')

        # Sanity Checks
        if end is not None and not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        else:
            params['end'] = time.mktime(end.timetuple())
            
        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        else:
            params['start'] = time.mktime(start.timetuple())
            
        if time_step not in ['Minute', 'Hour', 'Day']:
            raise ValueError("Invalid time_step: {0}".format(time_step))
        else:
            params['time_step'] = time_step

        # Send request
        return self._make_api_request('/servers/{0}/data/'.format(host_id), params=params)


    def get_server_outages(self, host_id, **kwargs):
        """
        This API lists the recent outages for the given server.

        Arguments:
            - host_id: required, first arg, non-keyword.
            - num: optional keyword, max number of data points to retrieve. Defaults to one.
            - end: optional keyword, retrieves data from this datetime object backwards. Defaults to current time.
            - start: optional keyword, won't retrieve data from before this datetime object.

        http://support.appfirst.com/apis/servers/#serveridoutages
        """
        params = {'limit': kwargs.get('num', 1)}
        end = kwargs.get('end', None)
        start = kwargs.get('start', None)

        # Sanity Checks
        if end is not None and not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        else:
            params['end'] = time.mktime(end.timetuple())
            
        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        else:
            params['start'] = time.mktime(start.timetuple())

        return self._make_api_request('/servers/{0}/outages/'.format(host_id))


    def get_polled_data_config(self, host_id):
        """
        Get the Polled Data config on a server.

        http://support.appfirst.com/apis/servers/#serveridpolleddata
        """
        return self._make_api_request('/servers/{0}/polled_data_config/'.format(host_id))


    def update_polled_data_config(self, host_id, data):
        """
        Update the Polled Data config on a server.

        Data should be a dictionary of updated fields like
        {'file_contents': 'Sample Content',
         'file_path': '/usr/local/nagios/etc/nrpe.cfg'}

        http://support.appfirst.com/apis/servers/#serveridpolleddata
        """
        if not isinstance(data, dict):
            raise TypeError("Data must be a dictionary")

        return self._make_api_request('/servers/{0}/polled_data_config/'.format(host_id), method='PUT', data=data)


    def get_server_tags(self, host_id):
        """
        Retrieves the server tag information for a particular server.

        http://support.appfirst.com/apis/servers/#serveridtags
        """
        return self._make_api_request('/servers/{0}/tags/'.format(host_id))


    def update_server_tags(self, host_id, new_tags):
        """
        Updates the server tags that this server belongs to.

        http://support.appfirst.com/apis/servers/#serveridtags
        """
        if not isinstance(new_tags, list):
            raise TypeError("new_tags must be a list")

        params = {'server_tags': json.dumps(new_tags)}
        return self._make_api_request('/servers/{0}/tags/'.format(host_id), params=params)


    def trigger_server_app_auto_detect(self, host_id):
        """
        Trigger auto application detection on this server. The result is a list
        application name that detected on this server.

        http://support.appfirst.com/apis/servers/#serveridautodetection
        """
        return self._make_api_request('/servers/{0}/auto_detection/'.format(host_id))


    # Process APIs
    def get_processes(self, host_id, **kwargs):
        """
        Returns the list of processes on a server. See the Processes API
        documentation for more information about process objects.

        Arguments:
            - host_id: required, first argument, non-keyword
            - end: optional keyword, datetime object for end-date of time range
            - start: optional keyword, datetime object for start-date of time range

        http://support.appfirst.com/apis/servers/#serveridprocesses
        """
        params = {}
        end = kwargs.get('end', None)
        start = kwargs.get('start', None)

        # Sanity Checks
        if end is not None and not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        else:
            params['end'] = time.mktime(end.timetuple())
            
        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        else:
            params['start'] = time.mktime(start.timetuple())
            
        return self._make_api_request('/servers/{0}/processes/'.format(host_id), params=params)


    def get_processes_data(self, host_id, **kwargs):
        """
        Returns the list of a processes’ summary data on a particular server.

        Arguments:
            - host_id: required, first arg, non-keyword.
            - num: optional keyword, max number of data points to retrieve. Defaults to one.
            - end: optional keyword, retrieves data from this datetime object backwards. Defaults to current time.
            - start: optional keyword, won't retrieve data from before this datetime object.
            - time_step: optional keyword, time step for the data. Can be 'Minute', 'Hour', 'Day'. Default is 'Minute'.

        http://support.appfirst.com/apis/servers/#serveridprocessesdata
        """
        params = {'num': kwargs.get('num', 1)}
        end = kwargs.get('end', None)
        start = kwargs.get('start', None)
        time_step = kwargs.get('time_step', 'Minute')

        # Sanity Checks
        if end is not None and not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        else:
            params['end'] = time.mktime(end.timetuple())
            
        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        else:
            params['start'] = time.mktime(start.timetuple())
            
        if time_step not in ['Minute', 'Hour', 'Day']:
            raise ValueError("Invalid time_step: {0}".format(time_step))
        else:
            params['time_step'] = time_step

        # Send request
        return self._make_api_request('/servers/{0}/processes/data/'.format(host_id), params=params)
