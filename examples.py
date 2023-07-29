from cpwebapi.session import APISession, GatewaySession, OAuthSession, OAuthConfig
from cpwebapi.oauth_utils import oauth_config_hook
import json


def request_examples(session: APISession):
    # Get the authentication status for the current session
    auth_status = session.auth_status()
    is_authenticated = auth_status["authenticated"]
    print(f"Authenticated: {is_authenticated}")


def market_data_examples(session: APISession):
    """
    Market data request examples for the EUR.USD currency pair (conid 12087792)

    In the case of market data snapshot requests we need to make two requests for each new conid requested, the first initializes the subscription, second returns the data.
    This is a limitation of the Client Portal API itself, and not the library itself.
    """
    conid = 12087792
    for _ in range(2):
        market_data = session.market_data_snapshot(conid_list=[conid], fields=["31"])
    print(market_data)
    historical_data = session.historical_market_data(conid=conid, period="1d", bar="1h")
    print(historical_data)


def gateway_session_example():
    session = GatewaySession(host="localhost", port=5000)
    request_examples(session)


def oauth_session_example(config_file_path: str):
    # In order to use OAuth, you need to create an OAuthConfig object and pass it to the OAuthSession constructor
    with open(config_file_path, "r") as f:
        oauth_config = json.load(f, object_hook=oauth_config_hook)
    session = OAuthSession(oauth_config=oauth_config)
    session.init_brokerage_session()
    request_examples(session)


def main():
    gateway_session_example()
    # oauth_session_example()


if __name__ == "__main__":
    main()
