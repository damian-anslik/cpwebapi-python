from cpwebapi import session, oauth_utils
import json

trading_env: str = "ppr"

# Load the OAuth config from a file
config_file_path = f"config.{trading_env}.json"
with open(config_file_path, "r") as f:
    oauth_config = json.load(f, object_hook=oauth_utils.oauth_config_hook)
# Initialise the OAuth session
oauth_session = session.OAuthSession(oauth_config=oauth_config)
# Initialise the brokerage session
oauth_session.init_brokerage_session()
# Get the authentication status
authentication_status = oauth_session.auth_status()
print(authentication_status.json())
