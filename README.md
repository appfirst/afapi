AppFirst's Python API Wrapper
=============================
[![Build Status](https://travis-ci.org/appfirst/afapi.svg)](https://travis-ci.org/appfirst/afapi)

This Python API wrapper allows clients to easily interact with AppFirst's APIs in a Python environment.


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
servers_list = api.get_servers()
alert = api.get_alert(231)
application = api.create_application("Apache", source_type='set', template_id=7)
```

#### Full documentation
A full list of API methods is available at **[this link]()**.