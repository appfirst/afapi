# encoding: utf-8

"""
Uses v5 of AppFirst's HTTP API

Full API documentation: http://support.appfirst.com/apis/
"""


import calendar
import datetime

try:
    import simplejson as json
except ImportError:
    import json

import requests
from requests.auth import HTTPBasicAuth

from . import exceptions

# Python3 compatibility
try:
    string_types = basestring
except NameError:
    string_types = str


class AppFirstAPI(object):
    """
    An object for connecting/authenticating with AppFirst APIs and retrieving
    different forms of data.
    """

    ok_codes = [200, 201, 202, 203, 204, 205, 206]

    def __init__(self, email, api_key,
                 base_url='https://wwws.appfirst.com/api', use_strict_ssl=True,
                 version=5, raise_exceptions=False, debug=False):
        self.email = email
        self.api_key = api_key
        self.base_url = base_url
        self.use_strict_ssl = use_strict_ssl
        self.version = version
        self.raise_exceptions = raise_exceptions
        self.debug = debug
        self.auth = HTTPBasicAuth(self.email, self.api_key)

    # Helper methods
    def _make_api_request(self, url, **kwargs):
        """
        Hits the API at `url` and returns the data from the request

        kwargs can be:
            - method:  defaults to 'GET'
            - params:  defaults to {}
            - data:    defaults to '' (for PUT requests)
            - headers: defaults to:
                {'accept': 'application/json; version=self.version'}
            - json_dump: defaults to False.
                Whether or not to dump data dictionary to JSON or let requests
                module encode it.
        """
        full_url = self.base_url + url
        method = kwargs.get('method', 'GET')
        params = kwargs.get('params', {})
        headers = {
            'accept': 'application/json; version={0}'.format(self.version),
        }
        headers.update(kwargs.get('headers', {}))
        data = kwargs.get('data', '')
        json_dump = kwargs.get('json_dump', False)

        if isinstance(data, dict) and json_dump:
            data = json.dumps(data)

        if method == 'GET':
            request_method = requests.get
        elif method == 'POST':
            request_method = requests.post
        elif method == 'PUT':
            request_method = requests.put
        elif method == 'PATCH':
            request_method = requests.patch
        elif method == 'DELETE':
            request_method = requests.delete
        else:
            raise ValueError("Invalid HTTP method: {0}".format(method))

        # Make request and check return status
        if self.debug:
            print(("> Making {0} request to {1}:\nparams={2}\ndata={3}\n"
                   "headers={4}".format(method, full_url, params, data,
                                        headers)))

        r = request_method(full_url, auth=self.auth, params=params, data=data,
                           headers=headers, verify=self.use_strict_ssl)
        if self.debug:
            print("< Got response with status: {0}".format(r.status_code))

        if r.status_code not in self.ok_codes and self.raise_exceptions:
            r_msg = u"{0.status_code}: {0.text}".format(r) \
                if r.text else r.status_code
            exc_msg = u"{0} reqeust to url {1} failed".format(method, full_url)
            raise exceptions.RequestError(u"{0} ({1})".format(exc_msg, r_msg))
        else:
            try:
                return (r.json(), r.status_code)
            except ValueError:
                return (r.text, r.status_code)

    def _get_list_params(self, **kwargs):
        """
        Function to get limit/page/filter arguments for API list requests
        - filter is a dictionary like {'hostname': 's05-room02'}
        """
        params = {}
        if 'limit' in kwargs:
            params['limit'] = kwargs['limit']
        if 'page' in kwargs:
            params['page'] = kwargs['page']
        if 'search' in kwargs:
            params['search'] = kwargs['search']
        if 'filter' in kwargs:
            params.update(kwargs['filter'])
        return params

    # Server APIs
    def get_servers(self, **kwargs):
        """
        Lists all available servers.

        http://support.appfirst.com/apis/servers/#servers
        """
        params = self._get_list_params(**kwargs)
        return self._make_api_request('/servers/', params=params)

    def get_server(self, host_id):
        """
        View a server.

        http://support.appfirst.com/apis/servers/#serverid
        """
        return self._make_api_request('/servers/{0}/'.format(host_id))

    def update_server(self, host_id, data):
        """
        Edit a server.
        Data argument should be a dict like {'nickname': 'new_nick'}

        http://support.appfirst.com/apis/servers/#serverid
        """
        if not isinstance(data, dict):
            raise TypeError("Data must be a dictionary")

        return self._make_api_request('/servers/{0}/'.format(host_id),
                                      data=data, method='PATCH')

    def delete_server(self, host_id):
        """
        Delete a server.

        http://support.appfirst.com/apis/servers/#serverid
        """
        return self._make_api_request('/servers/{0}/'.format(host_id),
                                      method='DELETE')

    def get_server_data(self, host_id, **kwargs):
        """
        Retrieves data for the given server.

        Arguments:
            - host_id: required, first arg, non-keyword.
            - num: optional keyword, max number of data points to retrieve.
                Defaults to one.
            - end: optional keyword, retrieves data from this datetime object
                backwards. Defaults to current time.
            - start: optional keyword, won't retrieve data from before this
                datetime object.
            - time_step: optional keyword, time step for the data.
                Can be 'Minute', 'Hour', 'Day'. Default is 'Minute'.

        http://support.appfirst.com/apis/servers/#serveriddata
        """
        params = {'num': kwargs.get('num', 1)}
        end = kwargs.get('end', None)
        start = kwargs.get('start', None)
        time_step = kwargs.get('time_step', 'Minute')

        # Sanity Checks
        if end is not None and not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        elif end is not None:
            params['end'] = calendar.timegm(end.timetuple())

        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        elif start is not None:
            params['start'] = calendar.timegm(start.timetuple())

        if time_step not in ['Minute', 'Hour', 'Day']:
            raise ValueError("Invalid time_step: {0}".format(time_step))
        else:
            params['time_step'] = time_step

        # Send request
        return self._make_api_request('/servers/{0}/data/'.format(host_id),
                                      params=params)

    def get_server_outages(self, host_id, **kwargs):
        """
        This API lists the recent outages for the given server.

        Arguments:
            - host_id: required, first arg, non-keyword.
            - num: optional keyword, max number of data points to retrieve.
                Defaults to one.
            - end: optional keyword, retrieves data from this datetime object
                backwards. Defaults to current time.
            - start: optional keyword, won't retrieve data from before this
                datetime object.

        http://support.appfirst.com/apis/servers/#serveridoutages
        """
        params = {'limit': kwargs.get('num', 1)}
        end = kwargs.get('end', None)
        start = kwargs.get('start', None)

        # Sanity Checks
        if end is not None and not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        elif end is not None:
            params['end'] = calendar.timegm(end.timetuple())

        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        elif start is not None:
            params['start'] = calendar.timegm(start.timetuple())

        return self._make_api_request('/servers/{0}/outages/'.format(host_id))

    def get_polled_data_config(self, host_id):
        """
        Get the Polled Data config on a server.

        http://support.appfirst.com/apis/servers/#serveridpolleddata
        """
        url = '/servers/{0}/polled_data_config/'.format(host_id)
        return self._make_api_request(url)

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

        url = '/servers/{0}/polled_data_config/'.format(host_id)
        return self._make_api_request(url, method='PATCH', data=data)

    def get_server_tags(self, host_id, **kwargs):
        """
        Retrieves the server tag information for a particular server.

        http://support.appfirst.com/apis/servers/#serveridtags
        """
        params = self._get_list_params(**kwargs)
        return self._make_api_request('/servers/{0}/tags/'.format(host_id),
                                      params=params)

    def update_server_tags(self, host_id, new_tags):
        """
        Updates the server tags that this server belongs to.

        http://support.appfirst.com/apis/servers/#serveridtags
        """
        if not isinstance(new_tags, list):
            raise TypeError("new_tags must be a list")

        data = {'server_tags': json.dumps(new_tags)}
        return self._make_api_request('/servers/{0}/tags/'.format(host_id),
                                      method='PATCH', data=data)

    def trigger_server_app_auto_detect(self, host_id):
        """
        Trigger auto application detection on this server. The result is a list
        application name that detected on this server.

        http://support.appfirst.com/apis/servers/#serveridautodetection
        """
        url = '/servers/{0}/auto_detection/'.format(host_id)
        return self._make_api_request(url)

    # Process APIs
    def get_server_processes(self, host_id, **kwargs):
        """
        Returns the list of processes on a server. See the Processes API
        documentation for more information about process objects.

        Arguments:
            - host_id: required, first argument, non-keyword
            - end: optional keyword, datetime object for end of time range
            - start: optional keyword, datetime object for start of time range

        http://support.appfirst.com/apis/servers/#serveridprocesses
        """
        params = {}
        end = kwargs.get('end', None)
        start = kwargs.get('start', None)

        # Sanity Checks
        if end is not None and not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        elif end is not None:
            params['end'] = calendar.timegm(end.timetuple())

        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        elif start is not None:
            params['start'] = calendar.timegm(start.timetuple())

        url = '/servers/{0}/processes/'.format(host_id)
        return self._make_api_request(url, params=params)

    def get_server_processes_data(self, host_id, **kwargs):
        """
        Returns the list of a processes’ summary data on a particular server.

        Arguments:
            - host_id: required, first arg, non-keyword.
            - num: optional keyword, max number of data points to retrieve.
                Defaults to one.
            - end: optional keyword, retrieves data from this datetime object
                backwards. Defaults to current time.
            - start: optional keyword, won't retrieve data from before this
                datetime object.
            - time_step: optional keyword, time step for the data.
                Can be 'Minute', 'Hour', 'Day'. Default is 'Minute'.

        http://support.appfirst.com/apis/servers/#serveridprocessesdata
        """
        params = {'num': kwargs.get('num', 1)}
        end = kwargs.get('end', None)
        start = kwargs.get('start', None)
        time_step = kwargs.get('time_step', 'Minute')

        # Sanity Checks
        if end is not None and not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        elif end is not None:
            params['end'] = calendar.timegm(end.timetuple())

        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        elif start is not None:
            params['start'] = calendar.timegm(start.timetuple())

        if time_step not in ['Minute', 'Hour', 'Day']:
            raise ValueError("Invalid time_step: {0}".format(time_step))
        elif time_step is not None:
            params['time_step'] = time_step

        # Send request
        url = '/servers/{0}/processes/data/'.format(host_id)
        return self._make_api_request(url, params=params)

    # Alert APIs
    def get_alerts(self, **kwargs):
        """
        Returns the list of alerts existing.

        http://support.appfirst.com/apis/alerts/#alerts
        """
        params = self._get_list_params(**kwargs)
        return self._make_api_request('/alerts/', params=params)

    def create_alert(self, name=None, alert_type=None, target_id=None,
                     trigger_type=None, users=[], **kwargs):
        """
        Creates alerts on processes based on documented requirements:

        - name (required, String, length:1-32) – the name of the alert.
        - target_id (required, String) – the system id of the target object.
            For process alerts, it should be a tuple with 4 elements:
            (server_id, pid, createtime, name)
        - trigger_type (required, String) – alert type decides what trigger
            types are available. - 'Process' – [
                'Process Termination', 'CPU', 'Memory',
                'Average Response Time', 'File Read', 'Files Write',
                'Inbound Network Traffic', 'Outbound Network Traffic',
                'Network Connections', 'Threads', 'Files', 'Registries',
                'Page Faults', 'Incident Reports', 'Critical Incident Reports',
                'Incident Report Content', 'File Accessed',
                'Registry Accessed', 'Port Accessed']

        Optional arguments are added at the end

        http://support.appfirst.com/apis/alerts/#alerts
        """
        # Set list of users
        if not isinstance(users, list) or len(users) == 0:
            raise ValueError("No users supplied to receive new alert!")
        data = {'users': json.dumps(users)}

        # Specify alert type
        alert_types = [
            'Process', 'Application', 'Log', 'Polled Data', 'Server',
            'Server Tag',
        ]
        if alert_type in alert_types:
            data['type'] = alert_type
        else:
            raise ValueError("Alert type specified must be one of "
                             "{0}".format(alert_types))

        # Check that name is not too long
        if len(name) <= 32:
            data['name'] = name
        else:
            raise ValueError("Name provided is too long. Must be no longer "
                             "than 32 characters.")

        # Check target id for process alert and other alerts
        if alert_type == 'Process' and len(target_id) != 4:
            raise ValueError("Process target id must have 4 parameters: "
                             "(server_id, pid, createtime, name)")
        elif alert_type == 'Process':
            data['target_id'] = ','.join([str(i) for i in target_id])
        else:
            data['target_id'] = target_id

        # Build list of trigger types based on alert type
        if alert_type == 'Process':
            trigger_types = [
                'Process Termination', 'CPU', 'Memory',
                'Average Response Time', 'File Read', 'File Write',
                'Inbound Network Traffic', 'Outbound Network Traffic',
                'Network Connections', 'Threads', 'Files', 'Registries',
                'Page Faults', 'Incident Reports', 'Critical Incident Reports',
                'Incident Report Content', 'File Accessed',
                'Registry Accessed', 'Port Accessed',
            ]
        elif alert_type == 'Server' or alert_type == 'Server Tag':
            trigger_types = [
                'Server Down', 'CPU', 'Memory', 'Average Response Time',
                'Disk', 'Disk Busy', 'Threads', 'Page Faults', 'Processes',
            ]
        elif alert_type == 'Log':
            trigger_types = [
                'Number of Info', 'Number of Warning', 'Number of Critical',
                'Log Content',
            ]
        elif alert_type == 'Polled Data':
            trigger_types = ['Nagios']
        elif alert_type == 'Application':
            trigger_types = [
                'Processes', 'Process Termination', 'CPU', 'Memory',
                'Average Response Time', 'File Read', 'File Write',
                'Inbound Network Traffic', 'Outbound Network Traffic',
                'Network Connections', 'Threads', 'Files', 'Registries',
                'Page Faults', 'Incident Reports', 'Critical Incident Reports',
                'Incident Report Content', 'File Accessed',
                'Registry Accessed', 'Port Accessed',
            ]

        # Check that trigger type specified is correct for specified alert type
        if trigger_type in trigger_types:
            data['trigger_type'] = trigger_type
        else:
            raise ValueError("Invalid trigger type for "
                             "{0} alert: {1}".format(alert_type, trigger_type))

        # Check and add optional arguments
        opt_args = [
            'active', 'direction', 'threshold', 'interval',
            'time_above_threshold', 'num_of_servers', 'threshold_type',
            'band_value', 'window_length', 'window_units', 'ip_details',
            'reg_exp',
        ]
        for arg in opt_args:
            if arg in kwargs:
                data[arg] = kwargs[arg]

        return self._make_api_request('/alerts/', data=data, method='POST')

    def delete_alert(self, alert_id):
        """
        Removes alert by specific alert id

        http://support.appfirst.com/apis/alerts/#alerts
        """
        return self._make_api_request('/alerts/{0}'.format(alert_id),
                                      method='DELETE')

    def get_alert(self, alert_id):
        """
        Returns current status of specific alert

        http://support.appfirst.com/apis-v3-alerts/#alertid
        """
        return self._make_api_request('/alerts/{0}'.format(alert_id))

    def get_alert_histories(self, **kwargs):
        """
        Lists recent alert histories.

        http://support.appfirst.com/apis/alert-histories/#alerthistories
        """
        params = self._get_list_params(**kwargs)
        return self._make_api_request('/alert_histories/', params=params)

    def get_alert_history(self, history_id):
        """
        View an alert history.

        http://support.appfirst.com/apis/alert-histories/#alerthistories
        """
        url = '/alert_histories/{0}/'.format(history_id)
        return self._make_api_request(url)

    def get_alert_history_message(self, hist_id):
        """
        View the email message content of an alert history.

        http://support.appfirst.com/apis/alert-histories/#alerthistories
        """
        url = '/alert_histories/{0}/message/'.format(hist_id)
        return self._make_api_request(url)

    # Server Tags
    def get_all_server_tags(self, **kwargs):
        """
        Lists all available server tags.

        http://support.appfirst.com/apis/server-tags/#servertags
        """
        params = self._get_list_params(**kwargs)
        return self._make_api_request('/server_tags/', params=params)

    def get_server_tag(self, tag_id):
        """
        Returns single server tag
        """
        return self._make_api_request('/server_tags/{0}'.format(tag_id))

    def create_server_tag(self, name, ids):
        """
        Create a new server tag.

        - name (required) – the name of the server tag,
            length must be 1 – 256 characters.
        - servers (required) – a list of server IDs.
        """
        if len(name) > 256:
            raise ValueError("Name is too long. Must be less than 256 "
                             "characters.")
        if not isinstance(ids, list):
            raise ValueError("IDs must be a list of server IDs.")
        data = {
            'name': name,
            'servers': ids,
        }
        return self._make_api_request('/server_tags/', data=data,
                                      method='POST')

    def delete_server_tag(self, tag_id):
        """
        Deletes a server tag
        """
        return self._make_api_request('/server_tags/{0}'.format(tag_id),
                                      method='DELETE')

    # Applications
    def get_process_groups(self, **kwargs):
        """
        Returns a dictionary of details for all definined applications.
        """
        params = self._get_list_params(**kwargs)
        return self._make_api_request('/applications/', params=params)

    def get_process_group(self, app_id):
        """
        Returns a dictionary of details for a specific application matching
        the given app_id
        """
        return self._make_api_request('/applications/{0}/'.format(app_id))

    def get_process_group_processes(self, app_id):
        """
        Returns a dictionary of processes used by specific app_id
        """
        url = '/applications/{0}/processes'.format(app_id)
        return self._make_api_request(url)

    def get_process_group_data(self, app_id, **kwargs):
        """
        Gets data for the given application. It gets up to "num" points
        starting from "end" and going back "start."

        http://support.appfirst.com/apis/applications/#applicationiddata
        """
        params = {
            'num': kwargs.get('num', None),
            'end': kwargs.get('end', None),
            'start': kwargs.get('start', None),
            'time_step': kwargs.get('time_step', None),
        }
        return self._make_api_request('/applications/{0}/data/'.format(app_id),
                                      params=params)

    def get_process_group_details(self, app_id, **kwargs):
        """
        Retrieves historical detail data for a given application.

        http://support.appfirst.com/apis/applications/#applicationiddetail
        """
        params = {'time': kwargs.get('time', None)}
        url = '/applications/{0}/detail/'.format(app_id)
        return self._make_api_request(url, params=params)

    def create_process_group(self, name=None, template_id=None,
                             source_type=None, **kwargs):
        """
        Creates an application based on the documented requirements:

        - name(required, String, length:1-32) - the name of the application
        - source_type(required, String) - either "servers" or "set"
        - servers(required if source_type==servers, list of server ids)
        - set(required if source_type==set, integer) - server set id
        - template_id(required, integer) - application template id

        Optional arguments are adding at the end
        """
        data = {'template': template_id}

        if isinstance(name, string_types) and len(name) <= 32:
            data['name'] = name
        else:
            raise ValueError("Name provided is too long. Must be no longer "
                             "than 32 characters.")

        if source_type == 'servers' and 'servers' in kwargs:
            data['source_type'] = 'servers'
            data['servers'] = kwargs.get('servers')
            if not isinstance(data['servers'], list) \
                    or len(data['servers']) == 0:
                raise ValueError("Received invalid list of servers for "
                                 "application definition.")

        elif source_type == 'set' and 'set' in kwargs:
            # Look up servers that are a part of this set
            data['source_type'] = 'set'
            data['set'] = kwargs['set']

        else:
            raise ValueError("Source Type must be either 'servers' or 'set' "
                             "and server ids or set id must be specified "
                             "in order to create application")

        return self._make_api_request('/applications/', data=data,
                                      method='POST')

    def delete_process_group(self, app_id):
        """
        Removes an application by specific application id
        """
        return self._make_api_request('/applications/{0}/'.format(app_id),
                                      method='DELETE')

    # Templates
    def get_process_templates(self, **kwargs):
        """
        Returns a dictionary for all defined templates
        """
        params = self._get_list_params(**kwargs)
        return self._make_api_request('/applications/templates/',
                                      params=params)

    def get_process_template(self, template_id):
        """
        Returns a dictionary of details for a specific template matching
        template_id
        """
        url = '/applications/templates/{0}/'.format(template_id)
        return self._make_api_request(url)

    def create_process_template(self, name=None, proc_name=None,
                                proc_args=None, proc_args_directions=None,
                                match_includes_args=True, rules=None):
        """
        Creates a template based on the documented requirements:

        - name(required, String, length:1-32) - the name of the template
        - rules - A list of rules of the format:
            ["Processes matching python with arguments matching *"]
        """
        if rules and isinstance(rules, list):
            # List of rules like
            #   ["Processes matching python with arguments matching *"]
            data = {'rules': rules}
        elif rules:
            raise TypeError("Rules must be a list of the format "
                            "[\"Processes matching python with arguments "
                            "matching *\"]")
        elif isinstance(proc_name, list):
            # List of multiple rules in separate format
            data = {
                'proc_name': proc_name,
                'proc_args': proc_args,
                'proc_args_direction': proc_args_directions,
            }
        else:
            raise Exception("Unable to parse process template parameters.")

        if len(name) <= 32:
            data['template_name'] = name
        else:
            raise ValueError("Name provided is too long. Must be no longer "
                             "than 32 characters.")

        return self._make_api_request('/applications/templates/', data=data,
                                      method='POST')

    def delete_process_template(self, template_id):
        """
        Removes a template by the specific template id
        """
        url = '/applications/templates/{0}/'.format(template_id)
        return self._make_api_request(url, method="DELETE")

    def get_process(self, server_id=None, pid=None, createtime=None, uid=None,
                    **kwargs):
        """
        Returns info about a process.
        Specify either a uid of the form "<server_id>_<pid>_<createtime>" or
        the individual server_id, pid, createtime.
        """
        if uid is None:
            uid = '{0}_{1}_{2}'.format(server_id, pid, createtime)
        return self._make_api_request('/processes/{0}/'.format(uid))

    def get_process_data(self, server_id=None, pid=None, createtime=None,
                         uid=None, **kwargs):
        """
        Returns data for a specific uid
        Specify either a uid of the form "<server_id>_<pid>_<createtime>" or
        the individual server_id, pid, createtime.
        """
        if uid is None:
            uid = '{0}_{1}_{2}'.format(server_id, pid, createtime)
        params = {'num': kwargs.get('num', 1)}
        end = kwargs.get('end', None)
        start = kwargs.get('start', None)
        time_step = kwargs.get('time_step', 'Minute')

        # Sanity Checks
        if end is not None and not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        elif end is not None:
            params['end'] = calendar.timegm(end.timetuple())

        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        elif start is not None:
            params['start'] = calendar.timegm(start.timetuple())

        if time_step not in ['Minute', 'Hour', 'Day']:
            raise ValueError("Invalid time_step: {0}".format(time_step))
        else:
            params['time_step'] = time_step

        return self._make_api_request('/processes/{0}/data/'.format(uid),
                                      params=params)

    def get_process_details(self, server_id, pid, createtime, **kwargs):
        """
        Retrieve detailed file/socket/thread/registry data for a process
        Specify either a uid of the form "<server_id>_<pid>_<createtime>" or
        the individual server_id, pid, createtime.
        http://support.appfirst.com/apis/processes/#processesdetail
        """
        uid = '{0}_{1}_{2}'.format(server_id, pid, createtime)
        params = {'time': kwargs['time']} if 'time' in kwargs else {}
        return self._make_api_request('/processes/{0}/detail/'.format(uid),
                                      params=params)

    def get_logs(self, **kwargs):
        """
        Returns the list of logs for this account.

        http://support.appfirst.com/apis/logs/#logs
        """
        params = self._get_list_params(**kwargs)
        return self._make_api_request('/logs/', params=params)

    def get_log(self, log_id):
        """
        View a log item.

        http://support.appfirst.com/apis/logs/#logid
        """
        return self._make_api_request('/logs/{0}'.format(log_id))

    def get_log_data(self, log_id, **kwargs):
        """
        Retrieves summary data for the given log.

        http://support.appfirst.com/apis/logs/#logiddata
        """
        return self._make_api_request('/logs/{0}/data/'.format(log_id))

    def get_users(self):
        """
        Retrieve a list of users on your account
        """
        return self._make_api_request('/users/')

    def get_user(self, user_id):
        """
        Retrieve details for a particular user
        """
        return self._make_api_request('/users/{0}/'.format(user_id))

    def create_user(self, first_name, last_name, email, country_code=1,
                    phone_number=None, avatar_url=None):
        """
        Create a new user profile for this tenant.

        Arguments

        first_name (required, String, length:1-30) – the first name of the new
            user profile.
        last_name (required, String, length:1-30) – the last name of the new
            user profile.
        email (required, String) – email address of this profile, it must be
            unique for each user profile.
            A valid email format is required. Once the user is successfully
            created, a confirmation email will be sent to the new user.
        country_code (required, int) – ISO country code for this user’s phone,
            required for sending SMS message.
        phone_number (required, int) – phone number of this user, required for
            sending SMS message.

        http://support.appfirst.com/apis/user-profiles/#userprofiles
        """
        if len(first_name) > 30 or len(last_name) > 30:
            raise ValueError("Name fields provided are too long. Must be no "
                             "longer than 30 characters.")
        if not isinstance(country_code, int):
            raise ValueError("Country code must be int")
        if not isinstance(phone_number, int):
            raise ValueError("Phone number must be int")
        if avatar_url and len(avatar_url) > 255:
            raise ValueError("Avatar field is too long. Must be no longer "
                             "than 30 characters.")
        data = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'country_code': country_code,
            'phone_number': phone_number,
            'avatar_url': avatar_url,
        }
        return self._make_api_request('/users/', data=data, method='POST')

    def update_user(self, user_id, first_name=None, last_name=None, email=None,
                    country_code=None, phone_number=None, avatar_url=None):
        """
        Update the information for this user.
        http://support.appfirst.com/apis/user-profiles/#userprofilesid
        """
        if (first_name and len(first_name) > 30) \
                or (last_name and len(last_name) > 30):
            raise ValueError("Name fields provided are too long. Must be no "
                             "longer than 30 characters.")
        if country_code and not isinstance(country_code, int):
            raise ValueError("Country code must be int")
        if phone_number and not isinstance(phone_number, int):
            raise ValueError("Phone number must be int")
        if avatar_url and len(avatar_url) > 255:
            raise ValueError("Avatar field is too long. Must be no longer "
                             "than 30 characters.")
        data = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'country_code': country_code,
            'phone_number': phone_number,
            'avatar_url': avatar_url,
        }
        return self._make_api_request('/users/{0}/'.format(user_id),
                                      data=data, method='PUT')

    def delete_user(self, user_id):
        """
        Delete a user profile. Account owner can NOT be deleted.

        http://support.appfirst.com/apis/user-profiles/#userprofilesid
        """
        return self._make_api_request('/users/{0}/'.format(user_id),
                                      method='DELETE')

    def get_account(self):
        """
        Return details about your account
        """
        return self._make_api_request('/account/')

    def get_maintenance_windows(self, **kwargs):
        """
        List all available maintenance windows.

        http://support.appfirst.com/apis/maintenance-windows/
        """
        params = self._get_list_params(**kwargs)
        return self._make_api_request('/maintenance_windows/', params=params)

    def get_maintenance_window(self, window_id):
        """
        List all available maintenance windows.

        http://support.appfirst.com/apis/maintenance-windows/
        """
        url = '/maintenance_windows/{0}'.format(window_id)
        return self._make_api_request(url)

    def create_maintenance_window(self, start, end, servers, **kwargs):
        """
        Create a new maintenance window.

        start (required) – start time in UTC time zone
            (ex: yyyy-mm-dd 24hr:mm).
        end (required) – end time in UTC time zone (ex: yyyy-mm-dd 24hr:mm).
        reason (optional)- reason for maintenance window.
        servers (required) – a list of server IDs.

        http://support.appfirst.com/apis/maintenance-windows/
        """
        # Sanity checks
        if not isinstance(servers, list):
            raise TypeError("severs argument must be provided as list")
        if not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        if not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")

        data = {
            'start': calendar.timegm(start.timetuple()),
            'end': calendar.timegm(end.timetuple()),
            'servers': servers,
        }
        if 'reason' in kwargs:
            data['reason'] = kwargs['reason']

        return self._make_api_request('/maintenance_windows/', data=data,
                                      method='POST')

    def update_maintenance_window(self, window_id, start, end, servers,
                                  **kwargs):
        """
        Update maintenance window with new information
        """
        # Sanity checks
        if not isinstance(servers, list):
            raise TypeError("severs argument must be provided as list")
        if not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        if not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")

        data = {
            'start': calendar.timegm(start.timetuple()),
            'end': calendar.timegm(end.timetuple()),
            'servers': servers,
        }
        if 'reason' in kwargs:
            data['reason'] = kwargs['reason']

        url = '/maintenance_windows/{0}/'.format(window_id)
        return self._make_api_request(url, data=data, method='PATCH')

    def delete_maintenance_window(self, window_id):
        """
        Removes maintenance window
        """
        url = '/maintenance_windows/{0}/'.format(window_id)
        return self._make_api_request(url, method='DELETE')

    def get_buckets(self, **kwargs):
        """
        Lists all available bucket data items.

        http://support.appfirst.com/apis/buckets/#buckets
        """
        params = self._get_list_params(**kwargs)
        return self._make_api_request('/buckets/', params=params)

    def get_bucket(self, bucket_id):
        """
        View or edit a bucket.

        http://support.appfirst.com/apis/buckets/#bucketid
        """
        return self._make_api_request('/buckets/{0}/'.format(bucket_id))

    def get_bucket_data(self, bucket_id, **kwargs):
        """
        Retrieves historical data for the given bucket.

        http://support.appfirst.com/apis/buckets/#bucketid
        """
        params = {'num': kwargs.get('num', 1)}
        end = kwargs.get('end', None)
        start = kwargs.get('start', None)
        time_step = kwargs.get('time_step', 'Minute')

        # Sanity Checks
        if end is not None and not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        elif end is not None:
            params['end'] = calendar.timegm(end.timetuple())

        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        elif start is not None:
            params['start'] = calendar.timegm(start.timetuple())

        if time_step not in ['Minute', 'Hour', 'Day']:
            raise ValueError("Invalid time_step: {0}".format(time_step))
        else:
            params['time_step'] = time_step

        return self._make_api_request('/buckets/{0}/data/'.format(bucket_id))

    def delete_bucket(self, bucket_id):
        """
        View or edit a bucket.

        http://support.appfirst.com/apis/buckets/#bucketid
        """
        return self._make_api_request('/buckets/{0}/'.format(bucket_id),
                                      method='DELETE')
