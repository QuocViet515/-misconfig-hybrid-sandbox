"""
Configuration management for the remediation pipeline
"""
import os
from dotenv import load_dotenv
from typing import Dict, Any

load_dotenv()


class Config:
    """Base configuration"""
    
    # AWS Configuration
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
    AWS_ACCOUNT_ID = os.getenv("AWS_ACCOUNT_ID", "")
    AWS_PROFILE = os.getenv("AWS_PROFILE", "default")
    
    # Azure Configuration
    AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "")
    AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID", "")
    
    # Elasticsearch/SIEM
    ELASTICSEARCH_HOST = os.getenv("ELASTICSEARCH_HOST", "localhost")
    ELASTICSEARCH_PORT = int(os.getenv("ELASTICSEARCH_PORT", 9200))
    ELASTICSEARCH_SCHEME = os.getenv("ELASTICSEARCH_SCHEME", "http")
    ELASTICSEARCH_USER = os.getenv("ELASTICSEARCH_USER", "elastic")
    ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "")
    ELASTICSEARCH_INDEX_PREFIX = os.getenv("ELASTICSEARCH_INDEX_PREFIX", "misconfig")
    
    # PostgreSQL
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "postgresql://user:password@localhost:5432/misconfig_db"
    )
    
    # Redis
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    REDIS_DB = int(os.getenv("REDIS_DB", 0))
    
    # Scanner Settings
    ENABLE_SCOUTSUITE = os.getenv("ENABLE_SCOUTSUITE", "true").lower() == "true"
    ENABLE_CLOUDSPLOIT = os.getenv("ENABLE_CLOUDSPLOIT", "true").lower() == "true"
    ENABLE_CHECKOV = os.getenv("ENABLE_CHECKOV", "true").lower() == "true"
    
    # Remediation Settings
    ENABLE_AUTO_REMEDIATION = os.getenv("ENABLE_AUTO_REMEDIATION", "false").lower() == "true"
    AUTO_REMEDIATE_SEVERITY_THRESHOLD = os.getenv("AUTO_REMEDIATE_SEVERITY_THRESHOLD", "LOW")
    MAINTENANCE_WINDOW = os.getenv("MAINTENANCE_WINDOW", "")
    
    # Notification
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
    TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "")
    JIRA_URL = os.getenv("JIRA_URL", "")
    JIRA_EMAIL = os.getenv("JIRA_EMAIL", "")
    JIRA_USERNAME = os.getenv("JIRA_USERNAME", "")
    JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN", "")
    JIRA_TOKEN = os.getenv("JIRA_TOKEN", "")
    JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "SEC")
    JIRA_ISSUE_TYPE = os.getenv("JIRA_ISSUE_TYPE", "Task")
    SERVICENOW_URL = os.getenv("SERVICENOW_URL", "")
    SERVICENOW_USER = os.getenv("SERVICENOW_USER", "")
    SERVICENOW_PASSWORD = os.getenv("SERVICENOW_PASSWORD", "")
    SERVICENOW_TABLE = os.getenv("SERVICENOW_TABLE", "incident")
    SERVICENOW_ASSIGNMENT_GROUP = os.getenv("SERVICENOW_ASSIGNMENT_GROUP", "Security Operations")
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = os.getenv("LOG_FORMAT", "json")
    
    # API
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", 8000))
    API_DEBUG = os.getenv("API_DEBUG", "false").lower() == "true"


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = False
    TESTING = True
    DATABASE_URL = "sqlite:///:memory:"


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    ENABLE_AUTO_REMEDIATION = True


def get_config(env: str = None) -> Config:
    """Get configuration based on environment"""
    if env is None:
        env = os.getenv("ENV", "development")
    
    config_map = {
        "development": DevelopmentConfig,
        "testing": TestingConfig,
        "production": ProductionConfig,
    }
    
    return config_map.get(env, DevelopmentConfig)()
