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

    def __init__(self, email, api_key, base_url='https://wwws.appfirst.com/api'):
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
            - json_dump: defaults to True. Whether or not to dump data dictionary.
        """
        full_url = self.base_url + url
        method = kwargs.get('method', 'GET')
        params = kwargs.get('params', {})
        headers = kwargs.get('headers', {})
        data = kwargs.get('data', '')
        json_dump = kwargs.get('json_dump', True)

        if isinstance(data, dict) and json_dump == True:
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
            try:
                return r.json()
            except ValueError:
                return r.text
        else:
            err_msg = u"{0}: {1}".format(r.status_code, r.text) if r.text != '' else r.status_code
            raise exceptions.RequestError(u"Server returned status code: {0}".format(err_msg))


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

        data_string = ""
        for key, item in data.iteritems():            
            data_string += "{0}={1}&".format(key, item)

        return self._make_api_request('/servers/{0}/'.format(host_id), data=data_string, method='PUT')


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
        elif end is not None:
            params['end'] = time.mktime(end.timetuple())

        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        elif start is not None:
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
        elif end is not None:
            params['end'] = time.mktime(end.timetuple())

        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        elif start is not None:
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
        return self._make_api_request('/servers/{0}/tags/'.format(host_id), method='PUT', params=params)


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
        elif end is not None:
            params['end'] = time.mktime(end.timetuple())

        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        elif start is not None:
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
        elif end is not None:
            params['end'] = time.mktime(end.timetuple())

        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        elif start is not None:
            params['start'] = time.mktime(start.timetuple())

        if time_step not in ['Minute', 'Hour', 'Day']:
            raise ValueError("Invalid time_step: {0}".format(time_step))
        elif time_step is not None:
            params['time_step'] = time_step

        # Send request
        return self._make_api_request('/servers/{0}/processes/data/'.format(host_id), params=params)


    # Alert APIs
    def get_alerts(self, **kwargs):
        """
        Returns the list of alerts existing.

        Arguments
            - limit (optional, default:2500, max:2500) – Sets the page size to a limit set by the user.
            - page (optional, default:0) – Retrieve the specific page of data of size limit.
            - filter_name (optional) – the type of object to filter the alerts. Must be one of “application_id”,
                ”process_id”,”server_id”, “polled_data_id”, “log_id”.
            - filter_id (optional) – The id of the objects, must be integer value.

        http://support.appfirst.com/apis/alerts/#alerts
        """
        filter_types = ["application_id", "process_id", "server_id", "polled_data_id", "log_id"]

        params = {'limit': kwargs.get('limit', 2500)}
        params['page'] = kwargs.get('page', 0)
        filter_name = kwargs.get('filter_name', None)
        params['filter_id'] = kwargs.get('filter_id', None)

        # Sanity check
        if filter_name is not None and filter_name not in filter_types:
            raise ValueError("Filter Name must be {0}".format(repr(filter_types)))
        else:
            params['filter_name'] = filter_name

        # Send request
        return self._make_api_request('/alerts/', params=params)


    def add_alert(self, name, alert_type, target_id, trigger_type, users, **kwargs):
        """
        Creates alerts on processes based on documented requirements:

        - name (required, String, length:1-32) – the name of the alert.
        - target_id (required, String) – the system id of the target object. It is a comma separated
            list for ‘Process’ alert (server id, process pid, process creation time and process name,
            or ‘server_id,pid,creationtime,myname’).
        - trigger_type (required, String) – alert type decides what trigger types are available.
            - ‘Process’ – ['Process Termination', 'CPU', 'Memory', 'Average Response Time', 'File Read',
            'Files Write', 'Inbound Network Traffic', 'Outbound Network Traffic', 'Network Connections',
            'Threads', 'Files', 'Registries', 'Page Faults', 'Incident Reports',
            'Critical Incident Reports', 'Incident Report Content', 'File Accessed', 'Registry Accessed', 'Port Accessed']

        Optional arguments are added at the end

        http://support.appfirst.com/apis/alerts/#alerts
        """
        # Add user data as json per documentation
        data = {'users': users}

        # Specify alert type
        alert_types = ["Process","Application","Log","Polled Data","Server", "Server Tag"]
        if alert_type in alert_types:
            data['type'] = alert_type
        else:
            raise ValueError("Alert type specified must be one of {0}".format(alert_types))

        # Check that name is not too long
        if len(name) < 32:
            data['name'] = name
        else:
            raise ValueError("Name provided is too long")

        # Check target id for process alert and other alerts
        if alert_type == "Process" and len(target_id.split(',')) != 4:
            raise ValueError("Process target id must have 4 parameters, server_id, pid, creationtime, myname")
        else:
            data['target_id'] = target_id

        # Build list of trigger types based on alert type
        if alert_type == "Process":
            trigger_types = ['Process Termination', 'CPU', 'Memory', 'Average Response Time',
                             'File Read', 'File Write', 'Inbound Network Traffic', 'Outbound Network Traffic',
                             'Network Connections', 'Threads', 'Files', 'Registries', 'Page Faults',
                             'Incident Reports', 'Critical Incident Reports', 'Incident Report Content',
                             'File Accessed', 'Registry Accessed', 'Port Accessed']
        elif alert_type == "Server" or alert_type=="Server Tag":
            trigger_types = ['Server Down', 'CPU', 'Memory', 'Average Response Time', 'Disk', 'Disk Busy',
                             'Threads', 'Page Faults', 'Processes']
        elif alert_type == "Log":
            trigger_types = ['Number of Info', 'Number of Warning', 'Number of Critical', 'Log Content']
        elif alert_type == "Polled Data":
            trigger_types = ['Nagios']
        elif alert_type == "Application":
            trigger_types = ['Processes', 'Process Termination', 'CPU', 'Memory', 'Average Response Time',
                             'File Read', 'File Write', 'Inbound Network Traffic', 'Outbound Network Traffic',
                             'Network Connections', 'Threads', 'Files', 'Registries', 'Page Faults',
                             'Incident Reports', 'Critical Incident Reports', 'Incident Report Content',
                             'File Accessed', 'Registry Accessed', 'Port Accessed']

        # Check that trigger type specified is correct for specified alert type
        if trigger_type in trigger_types:
            data['trigger_type'] = trigger_type
        else:
            raise ValueError("Trigger type is required or provided trigger type is not correct")

        # Check and add optional arguments
        opt_args = ['active', 'direction', 'threshold', 'interval', 'time_above_threshold', 'num_of_servers',
                    'threshold_type', 'band_value', 'window_length', 'window_units', 'ip_details', 'reg_exp']
        for arg in opt_args:
            if arg in kwargs: data[arg] = kwargs[arg]

        return self._make_api_request('/alerts/', data=data, method="POST",  json_dump = False )


    def remove_alert(self, alert_id):
        """
        Removes alert by specific alert id

        http://support.appfirst.com/apis/alerts/#alerts
        """
        return self._make_api_request('/alerts/{0}'.format(alert_id), method="DELETE")


    def get_alert(self, alert_id):
        """
        Returns current status of specific alert

        http://support.appfirst.com/apis-v3-alerts/#alertid
        """
        return self._make_api_request('/alerts/{0}'.format(alert_id))


    # Server Tags
    def get_all_server_tags(self, **kwargs):
        """
        Lists all available server tags.

        http://support.appfirst.com/apis/server-tags/#servertags
        """
        params = {
            'limit': kwargs.get('limit', 2500),
            'page': kwargs.get('page', 0),
            'filter': kwargs.get('filter_name', None),
        }
        return self._make_api_request('/server_tags/', params=params)


    def create_server_tag(self, name, ids):
        """
        Create a new server tag.

        - name (required) – the name of the server tag, length must be 1 – 256 characters.
        - servers (required) – a list of server IDs.
        """
        data = {
            'name': name,
            'servers': ids,
        }
        return self._make_api_request('/server_tags/', data=data, method="POST", json_dump=False)

    def delete_server_tag(self, tag_id):
        """
        Deletes a server tag
        """
        return self._make_api_request('/server_tags/{0}'.format(tag_id), method="DELETE")
	
    def get_server_tag(self, tag_id):
		"""
		Returns single server tag
		"""
		return self._make_api_request('/server_tags/{0}'.format(tag_id))

    # Applications
    def get_applications(self):
        """
        Returns a dictionary of details for all definined applications.
        """
        return self._make_api_request('/v4/applications/')


    def get_application(self, application_id):
        """
        Returns a dictionary of details for a specific application matching application_id
        """
        return self._make_api_request('/v4/applications/{0}/'.format(application_id))

    def get_appliation_processes(self, application_id):
        """
        Returns a dictionary of processes used by specific application id
        """
        return self._make_api_request('/v4/applications/{0}/processes'.format(application_id))
    
    def get_application_data(self, app_id, **kwargs):
        """
        Gets data for the given application. It gets up to “num” points starting from “end” and going back “start.”
        
        http://support.appfirst.com/apis/applications/#applicationiddata
        """
        
        params = {'num': kwargs.get('num', None)}
        params['end'] = kwargs.get('end', None)
        params['start'] = kwargs.get('start', None)
        params['time_step'] = kwargs.get('time_step', None)
        
        return self._make_api_request('/applications/{0}/data/'.format(app_id), params = params)
        
    def get_application_detail(self, app_id, **kwargs):
        """
        Retrieves historical detail data for a given application.
        
        http://support.appfirst.com/apis/applications/#applicationiddetail
        """
        
        params = {'time': kwargs.get('time', None)}
        
        return self._make_api_request('/applications/{0}/detail/'.format(app_id), params = params)

    def add_application(self, name, source_type, template_id, **kwargs):
        """
        Creates an application based on the documented requirements:

        - name(required, String, length:1-32) - the name of the application
        - source_type(required, String) - either "servers" or "set"
        - servers(required if source_type==servers, String of comma-separated server ids) - the list of server ids
        - set(required if source_type==set, integer) - server set id
        - template_id(required, integer) - application template id

        Optional arguments are adding at the end
        """
        data = {}

        if len(name) < 32:
            data['app_name'] = name
        else:
            raise ValueError("Name provided is too long")

        if source_type == 'servers':
            data['source_type'] = 'servers'
            data['servers'] = kwargs.get('servers', "")
        elif source_type == 'set':
            data['source_type'] = 'set'
            data['set'] = kwargs.get('set', "")
        else:
            raise ValueError("Source Type must be either 'servers' or 'set' to create application")

        data['template_id'] = template_id
        
        return self._make_api_request('/v4/applications/', data=data, method="POST", json_dump=False)


    def remove_application(self, application_id):
        """
        Removes an application by specific application id

        """
        return self._make_api_request('/v4/applications/{0}'.format(application_id), method="DELETE")


    # Templates
    def get_templates(self):
        """
        Returns a dictionary for all defined templates
        """
        return self._make_api_request('/v4/applications/templates/')


    def get_template(self, template_id):
        """
        Returns a dictionary of details for a specific template matching template_id
        """
        return self._make_api_request('/v4/applications/templates/{0}'.format(template_id))


    def add_template(self, name, proc_name, proc_args, proc_args_direction):
        """
        Creates a template based on the documented requirements:

        - name(required, String, length:1-32) - the name of the template
        - proc_name(required, regex String) - the name of the process to watch
        - proc_args(required, regex String) - the command line arguments the process should have
        - proc_args_direction(required, String, "include" or "exclude") - "include" for processes with
            arguments matching proc_args,"exclude" for processes with arguments not matching proc_args
        """
        data = {
            'proc_name': proc_name,
            'proc_args': proc_args,
            'proc_args_direction': proc_args_direction,
        }

        if len(name) < 32:
            data['template_name'] = name
        else:
            raise ValueError("Name provided is too long")

        return self._make_api_request('/v4/applications/templates/', data=data, method="POST", json_dump=False)

    def remove_template(self, template_id):
        """
        Removes a template by the specific template id
        """

        return self._make_api_request('/v4/applications/templates/{0}/'.format(template_id), method="DELETE")

    def get_process_data(self, uid, **kwargs):
        """
        Returns data for a specific uid
        """
        params = {'num': kwargs.get('num', 1)}
        end = kwargs.get('end', None)
        start = kwargs.get('start', None)
        time_step = kwargs.get('time_step', 'Minute')

        # Sanity Checks
        if end is not None and not isinstance(end, datetime.datetime):
            raise TypeError("end value must be a datetime.datetime instance")
        elif end is not None:
            params['end'] = time.mktime(end.timetuple())

        if start is not None and not isinstance(start, datetime.datetime):
            raise TypeError("start value must be a datetime.datetime instance")
        elif start is not None:
            params['start'] = time.mktime(start.timetuple())

        if time_step not in ['Minute', 'Hour', 'Day']:
            raise ValueError("Invalid time_step: {0}".format(time_step))
        else:
            params['time_step'] = time_step
        

        return self._make_api_request('/v4/processes/{0}/data/'.format(uid), params = params)

    def get_process_detail(self, uid, **kwargs):
        """
        Gets data for the given server.
        
        http://support.appfirst.com/apis/processes/#processesdetail
        """
        
        if 'time' in kwargs: params = {'time': kwargs['time']}
        
        return self._make_api_request('/processes/{0}/detail/'.format(uid), params = params)
    def get_logs(self, **kwargs):
        """
        Returns the list of logs for this account.

        http://support.appfirst.com/apis/logs/#logs
        """
        
        params = {'limit': kwargs.get('num', 1)}
        params['page'] = kwargs.get('page', 0)

        return self._make_api_request('/logs/', params = params)

    def get_log(self, log_id, **kwargs):
        """
        View a log item.

        http://support.appfirst.com/apis/logs/#logid
        """
        
        params = {'limit': kwargs.get('num', 1)}
        params['page'] = kwargs.get('page', 0)

        return self._make_api_request('/logs/{0}'.format(log_id), params = params)

    def get_log_data(self, log_id, **kwargs):
        """
        Retrieves summary data for the given log.
        
        http://support.appfirst.com/apis/logs/#logiddata
        """
        
        params = {'limit': kwargs.get('num', 1)}
        params['page'] = kwargs.get('page', 0)

        return self._make_api_request('/logs/{0}/data'.format(log_id), params = params)

    def get_user_profiles(self, **kwargs):
        """
        Lists all available user profiles or creates a new one. See above for the attributes each user profile has.
        
        http://support.appfirst.com/apis/user-profiles/#userprofiles
        """

        params = {'limit': kwargs.get('num', 2500)}
        params['page'] = kwargs.get('page', 0)
        if 'email' in kwargs: params['email'] = kwargs.get('email')

        return self._make_api_request('/user_profiles/', params = params)

    def get_user_profile(self, user_id, **kwargs):
        """
        View a user user_profile
        http://support.appfirst.com/apis/user-profiles/#userprofilesid
        """

        return self._make_api_request('/user_profiles/{0}'.format(user_id))

    def create_user_profile(self, first_name, last_name, email, country_code, phone_number):
        """
        Create a new user profile for this tenant.

        Arguments

        first_name (required, String, length:1-30) – the first name of the new user profile.
        last_name (required, String, length:1-30) – the last name of the new user profile.
        email (required, String) – email address of this profile, it must be unique for each user profile. A valid email format is required. Once the user is successfully created, a confirmation email will be sent to the new user.
        country_code (required, int) – ISO country code for this user’s phone, required for sending SMS message.
        phone_number (required, int) – phone number of this user, required for sending SMS message.

        http://support.appfirst.com/apis/user-profiles/#userprofiles
        """

        if len(first_name)>30 or len(last_name)>30:
            raise ValueError("Name provided is too long, must be length 1-30")

        if type(country_code)!= int:
            raise ValueError("Country code must be int")

        if type(phone_number)!= int:
             raise ValueError("Phone number must be int")

        data = {'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'country_code': country_code,
                'phone_number': phone_number}

        return self._make_api_request('/user_profiles/', data = data, method='POST', json_dump=False)


    def update_user_profile(self, user_id, data):
        """
        Update the information for this user.
        http://support.appfirst.com/apis/user-profiles/#userprofilesid
        """

        if not isinstance(data, dict):
            raise TypeError("Data must be a dictionary")

        data_string = ""
        for key, item in data.iteritems():            
            data_string += "{0}={1}&".format(key, item)
        
        return self._make_api_request('/user_profiles/{0}/'.format(user_id), data = data_string, method='PUT')

    def delete_user_profile(self, user_id):
        """
        Delete a user profile. Account owner can NOT be deleted.
        
        http://support.appfirst.com/apis/user-profiles/#userprofilesid
        """

        return self._make_api_request('/user_profiles/{0}/'.format(user_id), method='DELETE')
        
    def get_maintenance_window(self, window_id):
        """
        List all available maintenance windows.
        
        http://support.appfirst.com/apis/maintenance-windows/#maintenancewindows
        """
        
        return self._make_api_request('/maintenance_windows/{0}'.format(window_id))
    
    def get_maintenance_windows(self, **kwargs):
        """
        List all available maintenance windows.
        
        http://support.appfirst.com/apis/maintenance-windows/#maintenancewindows
        """
        params = {'limit': kwargs.get('num', 2500)}
        params['page'] = kwargs.get('page', 0)
        
        return self._make_api_request('/maintenance_windows/', params = params)
        
    def create_maintenance_window(self, start, end, servers, **kwargs):
        """
        Create a new maintenance window.

        start (required) – start time in UTC time zone (ex: yyyy-mm-dd 24hr:mm).
        end (required) – end time in UTC time zone (ex: yyyy-mm-dd 24hr:mm).
        reason (optional)- reason for maintenance window.
        servers (required) – a list of server IDs.
        
        http://support.appfirst.com/apis/maintenance-windows/#maintenancewindows
        """
        if type(servers) is not list: raise("severs argument must be provided as list")
        
        data = {'start': start, 'end': end, 'servers': servers}
        
        if 'reason' in kwargs: data['reason'] = kwargs['reason']
        
        return self._make_api_request('/maintenance_windows/', data=data, method="POST", json_dump=False)
    
    def delete_maintenance_window(self, window_id):
        """
        Removes maintenance window
        """
        
        return self._make_api_request('/maintenance_windows/{0}'.format(window_id), method='DELETE')
        
    def update_maintenance_window(self, window_id, start, end, servers, **kwargs):
        """
        Update maintenance window with new information
        """
        if type(servers) is not list: raise("severs argument must be provided as list")
        
        data = {'start': start, 'end': end, 'servers': servers}
        
        if 'reason' in kwargs: data['reason'] = kwargs['reason']
        
        return self._make_api_request('/maintenance_windows/{0}'.format(window_id), data = data, method='PUT')
        
    def create_mobile_device(self, brand, uid, **kwargs):
        """
        Create a new mobile device for this user. Requires the brand and uid parameters.

        It takes an additional boolean parameter “subscribe_all” that indicates whether the new device 
        should automatically be subscribed to all alerts for push notifications, or none. 
        
        http://support.appfirst.com/apis/mobile-devices/#mobiledevices
        """
        
        data = {'brand': brand, 'uid': uid}
        
        if 'subscribe_all' in kwargs: data['subscribe_all'] = kwargs['subscribe_all']
        
        return self._make_api_request('/mobile-devices/', data = data, method='POST')
        
    def get_alert_histories(self, **kwargs):
        """
        Lists recent alert histories.
        
        http://support.appfirst.com/apis/alert-histories/#alerthistories
        """
        params = {'limit': kwargs.get('limit', None)}
        params['page'] = kwargs.get('page', None)
        params['start'] = kwargs.get('start', None)
        params['filter'] = kwargs.get('filter', None)
        
        return self._make_api_request('/alert-histories/', params = params)
    
    def get_alert_history(self, history_id):
        """
        View an alert history.

        http://support.appfirst.com/apis/alert-histories/#alerthistories
        """
        
        return self._make_api_request('/alert-histories/{0}'.format(history_id))
        
    def get_alert_history_message(self, hist_id):
        """
        View the email message content of an alert history.
        
        http://support.appfirst.com/apis/alert-histories/#alerthistories
        """
        
        return self._make_api_request('/alert-histories/{0}/message/'.format(hist_id))
