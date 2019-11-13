import os

from typing import Dict, List, Set


def as_bool(value: str) -> bool:
    true_values = ('true', '1', 'yes', 'on')
    return value.lower() in true_values


class Config:
    auto_sync: bool
    auto_sync_interval: int
    aws_access_key_id: str
    aws_default_region: str
    aws_ignored_security_groups: Set
    aws_secret_access_key: str
    aws_ses_configuration_set: str
    az_auth_endpoint: str
    az_client_id: str
    az_client_secret: str
    az_tenant_id: str
    azure_token_endpoint: str
    bootstrap_admin: str
    clouds_to_sync: str
    db: str
    debug_layout: bool
    feature_flags: List
    log_format: str
    log_level: str
    other_log_levels: Dict[str, str] = {}
    openid_conf_url: str
    permanent_sessions: bool
    power_control_domain: str
    reset_database: bool
    scheme: str
    secret_key: str
    send_email: bool
    server_name: str
    smtp_from: str
    smtp_host: str
    smtp_password: str
    smtp_username: str
    support_email: str
    tz: str
    version: str
    zendesk_widget_key: str

    def __init__(self):
        """Instantiating a Config object will automatically read the following environment variables:

        APP_VERSION, AUTO_SYNC, AUTO_SYNC_INTERVAL, AWS_ACCESS_KEY_ID, AWS_DEFAULT_REGION, AWS_IGNORED_SECURITY_GROUPS,
        AWS_SECRET_ACCESS_KEY, AWS_SES_CONFIGURATION_SET, AZ_CLIENT_ID, AZ_CLIENT_SECRET, AZ_TENANT_ID, BOOTSTRAP_ADMIN,
        CLOUDS_TO_SYNC, DB, DEBUG_LAYOUT, FEATURE_FLAGS, LOG_FORMAT, LOG_LEVEL, OTHER_LOG_LEVELS, PERMANENT_SESSIONS,
        POWER_CONTROL_DOMAIN, RESET_DATABASE, SCHEME, SECRET_KEY, SEND_EMAIL, SERVER_NAME, SMTP_FROM, SMTP_HOST,
        SMTP_PASSWORD, SMTP_USERNAME, SUPPORT_EMAIL, TZ, ZENDESK_WIDGET_KEY

        Some variables have defaults if they are not found in the environment:

        AUTO_SYNC_INTERVAL=10
        AWS_DEFAULT_REGION=us-west-2
        CLOUDS_TO_SYNC=aws,az
        LOG_FORMAT="%(levelname)s [%(name)s] %(message)s"
        LOG_LEVEL=INFO
        PERMANENT_SESSIONS=False
        RESET_DATABASE=False
        SCHEME=http
        SEND_EMAIL=False
        SERVER_NAME=localhost:8080
        TZ=Etc/UTC
        """

        self.auto_sync = as_bool(os.getenv('AUTO_SYNC'))
        self.auto_sync_interval = int(os.getenv('SYNC_INTERVAL', '10'))
        self.aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
        self.aws_default_region = os.getenv('AWS_DEFAULT_REGION', 'us-west-2')
        self.aws_ignored_security_groups = set(os.getenv('AWS_IGNORED_SECURITY_GROUPS', '').split())
        self.aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.aws_ses_configuration_set = os.getenv('AWS_SES_CONFIGURATION_SET')
        self.az_client_id = os.getenv('AZ_CLIENT_ID')
        self.az_client_secret = os.getenv('AZ_CLIENT_SECRET')
        self.az_tenant_id = os.getenv('AZ_TENANT_ID')
        self.bootstrap_admin = os.getenv('BOOTSTRAP_ADMIN')
        self.clouds_to_sync = os.getenv('CLOUDS_TO_SYNC', 'aws,az')
        self.db = os.getenv('DB')
        self.debug_layout = as_bool(os.getenv('DEBUG_LAYOUT', 'False'))
        self.feature_flags = os.getenv('FEATURE_FLAGS', '').split()
        self.log_format = os.getenv('LOG_FORMAT', '%(levelname)s [%(name)s] %(message)s')
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.permanent_sessions = as_bool(os.getenv('PERMANENT_SESSIONS', 'False'))
        self.power_control_domain = os.getenv('POWER_CONTROL_DOMAIN')
        self.reset_database = as_bool(os.getenv('RESET_DATABASE', 'False'))
        self.scheme = os.getenv('SCHEME', 'http')
        self.secret_key = os.getenv('SECRET_KEY')
        self.send_email = as_bool(os.getenv('SEND_EMAIL', 'False'))
        self.server_name = os.getenv('SERVER_NAME', 'localhost:8080')
        self.smtp_from = os.getenv('SMTP_FROM')
        self.smtp_host = os.getenv('SMTP_HOST')
        self.smtp_password = os.getenv('SMTP_PASSWORD')
        self.smtp_username = os.getenv('SMTP_USERNAME')
        self.support_email = os.getenv('SUPPORT_EMAIL')
        self.tz = os.getenv('TZ', 'Etc/UTC')
        self.version = os.getenv('APP_VERSION', 'unknown')
        self.zendesk_widget_key = os.getenv('ZENDESK_WIDGET_KEY')

        for log_spec in os.getenv('OTHER_LOG_LEVELS', '').split():
            logger, level = log_spec.split(':', maxsplit=1)
            self.other_log_levels[logger] = level

        self.az_auth_endpoint = f'https://login.microsoftonline.com/{self.az_tenant_id}/oauth2/v2.0/authorize'
