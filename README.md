AppFirst's Python API Wrapper
=============================
[![Build Status](https://travis-ci.org/appfirst/afapi.svg)](https://travis-ci.org/appfirst/afapi)

This Python API wrapper allows clients to easily interact with AppFirst's APIs
in a Python environment. Compatible with Python 2.6+ including Python 3.

Installation
------------

```
$ sudo pip install afapi
```

Or, clone the repository, cd into the new directory, and run:
```
$ sudo python setup.py install
```

Usage
-----

#### Setup
```python
from afapi import AppFirstAPI

# pass_key is user's login password or account API key
api = AppFirstAPI('your@email.com', 'pass_key')
```

#### Basic usage
```python
# Get a list of all servers
servers_list = api.get_servers()

# Get aggregated data for a server with id 11374
server_data = api.get_server_data(11374, num=10)

# Get a list of StatsD buckets of a particular type
buckets = api.get_buckets(filter={'type': 'gauge'})

# Search for process groups
proc_groups = api.get_process_groups(search='python')

# Get details for a particular alert with id 231
alert = api.get_alert(231)

# Create a new process group
application = api.create_process_group("Nginx", template_id=372,
                                       source_type='set', set=8092)
```

For most data types, the methods follow the following format:

```python
api.get_objects()  # kwargs for filter/search/limit
api.get_object(object_id) 
api.get_object_data(object_id)  # kwargs for start/end/num/time_step
api.create_object(*args, **kwargs)
api.update_object(object_id, *args, **kwargs)
api.delete_object(object_id)
```

Each request will return a tuple containing
`(return_data, return_status_code)`. An exception can be optionally thrown on
non-200 return codes by passing the `raise_exceptions=True` flag when creating
the `AppFirstAPI` instance.
