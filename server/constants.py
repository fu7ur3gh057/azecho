AUTH_PROVIDERS = {'email': 'email', 'google': 'google', 'facebook': 'facebook', 'twitter': 'twitter'}

CELERY_PRIORITY = {
    'EMAIL': 7,
    'SUBSCRIPTION': 9,
    'CRAWLER': 5,
    'DIVER': 3,
    'GENERATOR': 9,
}
