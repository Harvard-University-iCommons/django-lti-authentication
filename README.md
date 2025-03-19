# django-lti-authentication

Add-on to `django-lti` that integrates with Django's user authentication system.

Setup
-----

Start by adding `lti_authentication.backends.LtiLaunchAuthenticationBackend` to your project's `AUTHENTICATION_BACKENDS`.

```
AUTHENTICATION_BACKENDS = [
    ...
    'lti_tool.auth.backends.LtiLaunchAuthenticationBackend',
]
```

Then, add `lti_tool.auth.middleware.LtiLaunchAuthenticationMiddleware` to the `MIDDLEWARE` setting.
It's important to list the `LtiLaunchAuthenticationMiddleware` *after* `LtiLaunchMiddleware` and
`AuthenticationMiddleware`.

```
MIDDLEWARE = [
    'lti_tool.middleware.LtiLaunchMiddleware',
    ...
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'lti_tool.auth.middleware.LtiLaunchAuthenticationMiddleware',
]
```

Configuring the Django username
-------------------------------

By default, the username is set to the `sub` value from the LTI launch.  You can use the `person_sourcedid`
value from the `lis` claim instead by adding this to your Django settings:

```
LTI_AUTHENTICATION = {
    'use_person_sourcedid': True,
}
```
If you want to use a different field, you can subclass `LtiLaunchAuthenticationBackend` and override the
`get_username` method.