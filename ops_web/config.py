import os

from typing import Dict, List


class Config:
    auto_sync: bool
    auto_sync_interval: int
    aws_access_key_id: str
    aws_default_region: str
    aws_secret_access_key: str
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
    rep_sc_pairs_db: str
    reset_database: bool
    scheme: str
    secret_key: str
    support_email: str
    tz: str
    version: str

    def __init__(self):
        """Instantiating a Config object will automatically read the following environment variables:

        APP_VERSION, AUTO_SYNC, AUTO_SYNC_INTERVAL, AWS_ACCESS_KEY_ID, AWS_DEFAULT_REGION, AWS_SECRET_ACCESS_KEY,
        AZ_CLIENT_ID, AZ_CLIENT_SECRET, AZ_TENANT_ID, BOOTSTRAP_ADMIN, CLOUDS_TO_SYNC, DB, DEBUG_LAYOUT, FEATURE_FLAGS,
        LOG_FORMAT, LOG_LEVEL, OTHER_LOG_LEVELS, PERMANENT_SESSIONS, POWER_CONTROL_DOMAIN, REP_SC_PAIRS_DB,
        RESET_DATABASE, SCHEME, SECRET_KEY, SUPPORT_EMAIL, TZ

        Some variables have defaults if they are not found in the environment:

        AUTO_SYNC_INTERVAL=10
        AWS_DEFAULT_REGION=us-west-2
        CLOUDS_TO_SYNC=aws,az
        LOG_FORMAT="%(levelname)s [%(name)s] %(message)s"
        LOG_LEVEL=INFO
        PERMANENT_SESSIONS=false
        RESET_DATABASE=false
        SCHEME=http
        TZ=Etc/UTC
        """

        _true_values = ('true', '1', 'yes', 'on')
        self.auto_sync = os.getenv('AUTO_SYNC').lower() in _true_values
        self.auto_sync_interval = int(os.getenv('SYNC_INTERVAL', '10'))
        self.aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
        self.aws_default_region = os.getenv('AWS_DEFAULT_REGION', 'us-west-2')
        self.aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.az_client_id = os.getenv('AZ_CLIENT_ID')
        self.az_client_secret = os.getenv('AZ_CLIENT_SECRET')
        self.az_tenant_id = os.getenv('AZ_TENANT_ID')
        self.bootstrap_admin = os.getenv('BOOTSTRAP_ADMIN')
        self.clouds_to_sync = os.getenv('CLOUDS_TO_SYNC', 'aws,az')
        self.db = os.getenv('DB')
        self.debug_layout = os.getenv('DEBUG_LAYOUT', 'false').lower() in _true_values
        self.feature_flags = os.getenv('FEATURE_FLAGS', '').split()
        self.log_format = os.getenv('LOG_FORMAT', '%(levelname)s [%(name)s] %(message)s')
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.permanent_sessions = os.getenv('PERMANENT_SESSIONS', 'false').lower() in _true_values
        self.power_control_domain = os.getenv('POWER_CONTROL_DOMAIN')
        self.rep_sc_pairs_db = os.getenv('REP_SC_PAIRS_DB')
        self.reset_database = os.getenv('RESET_DATABASE', 'false').lower() in _true_values
        self.scheme = os.getenv('SCHEME', 'http')
        self.secret_key = os.getenv('SECRET_KEY')
        self.support_email = os.getenv('SUPPORT_EMAIL')
        self.tz = os.getenv('TZ', 'Etc/UTC')
        self.version = os.getenv('APP_VERSION', 'unknown')

        for log_spec in os.getenv('OTHER_LOG_LEVELS', '').split():
            logger, level = log_spec.split(':', maxsplit=1)
            self.other_log_levels[logger] = level

        self.az_auth_endpoint = f'https://login.microsoftonline.com/{self.az_tenant_id}/oauth2/v2.0/authorize'
