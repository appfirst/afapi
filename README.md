AppFirst's Python API Wrapper
=============================
[![Build Status](https://travis-ci.org/appfirst/afapi.svg)](https://travis-ci.org/appfirst/afapi)

This Python API wrapper allows clients to easily interact with AppFirst's APIs
in a Python environment.


Examples
--------

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

# Get details for a particular alert
alert = api.get_alert(231)

# Create a new process group
application = api.create_process_group("Nginx", source_type='set',
                                       template_id=7)
```

For most data types, the methods follow the following format:

```python
api.get_objects()
api.get_object(object_id)
api.create_object(*args, **kwargs)
api.update_object(object_id, *args, **kwargs)
api.delete_object(object_id)
```

Each request will return a tuple containing
`(return_status_code, return_data)`. An exception can be optionally thrown on
non-200 return codes by passing the `raise_exceptions=True` flag when creating
the AppFirstAPI instance.

#### Full documentation
A full list of API methods is available at **[this link]()**.
