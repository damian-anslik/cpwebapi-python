import datetime
import requests
import dataclasses
import functools
import inspect
import urllib3
import logging
from urllib3 import exceptions
from urllib import parse
from typing import Any
from .oauth_utils import (
    read_private_key,
    generate_rsa_sha_256_signature,
    generate_base_string,
    generate_authorization_header_string,
    generate_oauth_nonce,
    generate_dh_challenge,
    generate_dh_random_bytes,
    calculate_live_session_token,
    calculate_live_session_token_prepend,
    generate_hmac_sha_256_signature,
    validate_live_session_token,
    OAuthConfig,
)

# Disable insecure request warnings when connecting via Gateway
urllib3.disable_warnings(exceptions.InsecureRequestWarning)


@dataclasses.dataclass
class APIRequest:
    params: dict[str, Any] = dataclasses.field(default=None)
    body: dict[str, Any] = dataclasses.field(default=None)
    form_data: dict[str, Any] = dataclasses.field(default=None)
    prepend: str = dataclasses.field(default=None)
    extra_headers: dict[str, str] = dataclasses.field(default=None)


def request(method: str, endpoint: str):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            # Bind the function arguments to the function signature.
            func_signature = inspect.signature(func).bind(self, *args, **kwargs)
            func_signature.apply_defaults()
            func_args_and_params = func_signature.arguments
            formatted_endpoint = endpoint.format(**func_args_and_params)
            request_data = func(self, *args, **kwargs)
            if not request_data:
                request_data = APIRequest()
            response = self.make_api_request(method, formatted_endpoint, request_data)
            if not response.ok:
                response.raise_for_status()
            response_data = response.json()
            return response_data

        return wrapper

    return decorator


class APISession:
    # Session endpoints

    @request("POST", "tickle")
    def tickle(self):
        """
        Tickle the session to keep it alive.
        """
        pass

    @request("POST", "logout")
    def logout(self):
        """
        Logout of the session.
        """
        pass

    @request("GET", "iserver/auth/status")
    def auth_status(self):
        """
        Get the authentication status for the current session.
        """
        pass

    @request("POST", "iserver/reauthenticate")
    def reauthenticate(self):
        """
        Reauthenticate the session.
        """
        pass

    @request("GET", "one/user")
    def user_details(self):
        pass

    # Contract operations

    @request("GET", "trsrv/secdef")
    def secdef_by_conid(self, conid_list: list[int]):
        """
        Get security definitions by conid. This endpoint does not require a brokerage session.
        """
        request_data = APIRequest(
            params={"conids": ",".join([str(conid) for conid in conid_list])}
        )
        return request_data

    @request("GET", "trsrv/secdef/schedule")
    def trading_schedule(
        self,
        symbol: str,
        asset_class: str,
        exchange: str = None,
        exchange_filter: str = None,
    ):
        """
        Returns the trading schedule for the requested symbol up to a month in advance.
        """
        request_data = APIRequest(
            params={
                "symbol": symbol,
                "assetClass": asset_class,
                "exchange": exchange,
                "exchangeFilter": exchange_filter,
            }
        )
        return request_data

    @request("GET", "trsrv/futures")
    def futures_by_symbol(self, symbol_list: list[str]):
        """
        Returns a list of non-expired future contracts for a given symbol.
        """
        request_data = APIRequest(params={"symbols": ",".join(symbol_list)})
        return request_data

    @request("GET", "trsrv/stocks")
    def stocks_by_symbol(self, symbol_list: list[str]):
        """
        Get stocks by symbol. This endpoint does not require a brokerage session.
        """
        request_data = APIRequest(params={"symbols": ",".join(symbol_list)})
        return request_data

    @request("GET", "iserver/contract/{conid}/info")
    def contract_details(self, conid: int):
        """
        Get details for the specified contract identifier.
        """
        pass

    @request("POST", "iserver/secdef/search")
    def search_by_symbol_or_name(
        self, search_term: str, is_name: bool = True, asset_class: str = None
    ):
        """
        Search for a contract by symbol or name.
        """
        request_data = APIRequest(
            body={"symbol": search_term, "name": is_name, "secType": asset_class}
        )
        return request_data

    @request("GET", "iserver/secdef/strikes")
    def search_strikes(
        self, conid: int, asset_class: str, month: str, exchange: str = "SMART"
    ):
        """
        Get a list of strikes for the specified contract identifier. For available contract months and exchanges
        use the `search_by_symbol_or_name` endpoint.
        """
        if asset_class.upper() not in ["OPT", "WAR"]:
            raise ValueError("Asset class must be OPT or WAR")
        request_data = APIRequest(
            params={
                "conid": str(conid),
                "secType": asset_class,
                "month": month,
                "exchange": exchange,
            }
        )
        return request_data

    @request("GET", "iserver/secdef/info")
    def secdef_info(
        self,
        conid: int,
        asset_class: str,
        month: str = None,
        exchange: str = "SMART",
        strike: float = None,
        right: str = None,
    ):
        VALID_ASSET_CLASSES = ["FUT", "OPT", "WAR", "CASH", "CFD"]
        asset_class_upper = asset_class.upper()
        if asset_class_upper not in VALID_ASSET_CLASSES:
            raise ValueError(
                "Asset class must be one of {}".format(VALID_ASSET_CLASSES)
            )
        if asset_class_upper in ["FUT", "OPT", "WAR"] and not month:
            raise ValueError(
                "Month must be specified for asset class {}".format(asset_class_upper)
            )
        if asset_class_upper in ["OPT", "WAR"] and not strike:
            raise ValueError(
                "Strike must be specified for asset class {}".format(asset_class_upper)
            )
        if asset_class_upper in ["OPT", "WAR"] and not right:
            raise ValueError(
                "Right must be specified for asset class {}".format(asset_class_upper)
            )
        request_data = APIRequest(
            params={
                "conid": str(conid),
                "secType": asset_class,
                "month": month,
                "exchange": exchange,
                "strike": strike,
                "right": right,
            }
        )
        return request_data

    @request("GET", "iserver/contract/{conid}/algos")
    def algo_params(
        self,
        conid: int,
        algo_list: list[str] = None,
        add_algo_description: bool = False,
        add_algo_params: bool = False,
    ):
        """
        Get a list of supported algos for the specified contract identifier. Must be called a second time to get the full
        list of parameters for each algo.
        """
        request_data = APIRequest(
            params={
                "algos": ";".join(algo_list) if algo_list else None,
                "addAlgoDescription": int(add_algo_description),
                "addAlgoParams": int(add_algo_params),
            }
        )
        return request_data

    @request("POST", "iserver/contract/rules")
    def contract_rules(self, conid: int, is_buy: bool = True):
        """
        Get a list of rules for the specified contract identifier.
        """
        request_data = APIRequest(body={"conid": conid, "isBuy": is_buy})
        return request_data

    @request("GET", "iserver/contract/{conid}/info-and-rules")
    def contract_info_and_rules(self, conid: int, is_buy: bool = True):
        """
        Get both contract details and rules for the specified contract identifier.
        For only contract details, use the `contract_details` endpoint.
        For only rules, use the `contract_rules` endpoint.
        """
        request_data = APIRequest(params={"isBuy": is_buy})
        return request_data

    @request("GET", "ibcust/marketdata/subscriptions")
    def market_data_subscriptions(self):
        """
        Get a list of all market data subscriptions. This endpoint does not require a brokerage session.
        """
        pass

    # Market data

    @request("GET", "iserver/marketdata/snapshot")
    def market_data_snapshot(self, conid_list: list[int], fields: list[str]):
        """
        Returns a snapshot of market data for a list of conids. The fields parameter contains a list of fields to be returned.
        This endpoint needs to be called at least twice, with the first call initiating the subscription and the second call returning the data.
        """
        request_data = APIRequest(
            params={
                "conids": ",".join([str(conid) for conid in conid_list]),
                "fields": ",".join([str(field) for field in fields]),
            }
        )
        return request_data

    @request("GET", "iserver/marketdata/{conid}/unsubscribe")
    def cancel_market_data_single(self, conid: int):
        """
        Unsubscribe from market data for a given conid.
        """
        pass

    @request("GET", "iserver/marketdata/unsubscribeall")
    def cancel_market_data_all(self):
        """
        Cancel all market data subscriptions.
        """
        pass

    @request("GET", "iserver/marketdata/history")
    def historical_market_data(
        self,
        conid: str,
        period: str,
        bar: str,
        exchange: str = None,
        start_time: datetime.datetime = None,
        outside_rth: bool = False,
    ):
        """
        Get historical OHLVC data for a given conid.
        """
        if start_time:
            if (
                start_time.hour == 0
                and start_time.minute == 0
                and start_time.second == 0
            ):
                start_time = start_time.replace(hour=23, minute=59, second=59)
        request_data = APIRequest(
            params={
                "conid": conid,
                "exchange": exchange,
                "period": period,
                "bar": bar,
                "outsideRth": outside_rth,
                "startTime": start_time.strftime("%Y%m%d-%H:%M:%S")
                if start_time
                else None,
            }
        )
        return request_data

    # Scanner

    @request("GET", "iserver/scanner/params")
    def scanner_params(self):
        """
        Get a list of supported scanner parameters.
        """
        pass

    # TODO Figure out how the Scanner Run method is meant to work

    # Trades

    @request("GET", "iserver/account/trades")
    def trades(self):
        """
        Returns a list of trades for the currently selected account.
        """
        pass

    # PnL

    @request("GET", "iserver/account/pnl/partitioned")
    def partitioned_pnl(self):
        """
        Returns the PNl for the currently selected account and its models (if any).
        """
        pass

    # Account & Portfolio

    @request("GET", "portfolio/accounts")
    def portfolio_accounts(self):
        """
        In non-tiered account structures, returns a list of accounts for which the user
        can view position and account information. For querying accounts which the user can trade see the brokerage_accounts
        method.
        """
        pass

    @request("GET", "portfolio/subaccounts")
    def portfolio_subaccounts(self):
        """
        Used in tiered account structures (FA, iBrokers). Returns up to 100 sub-accounts for which the
        user can view position and account-related inforamtion.
        """
        pass

    @request("GET", "portfolio/subaccounts2")
    def portfolio_subaccounts_paginated(self, page: int = 0):
        """
        Returns a paginated list of accounts for which the user can view position and account-related information.
        Returns 20 accounts per page. If you have less than 100 subaccounts use the portfolio_subaccounts method instead.
        """
        request_data = APIRequest(params={"page": page})
        return request_data

    @request("GET", "portfolio/{account_id}/meta")
    def account_information(self, account_id: str):
        """
        Returns information about the given account id.
        """
        pass

    @request("GET", "portfolio/{account_id}/summary")
    def account_summary(self, account_id: str):
        """
        Returns the portfolio summary for the given account id including information about margin,
        cash balances and other information related to the account.
        """
        pass

    @request("GET", "portfolio/{account_id}/ledger")
    def account_ledger(self, account_id: str):
        """
        Information regarding settled cash, cash balances, etc. in the account's base currency and any other cash
        balances held in other currencies.
        """
        pass

    @request("GET", "iserver/accounts")
    def brokerage_accounts(self):
        """
        Returns a list of brokerage accounts associated that the user has access to.
        """
        pass

    @request("POST", "iserver/switch")
    def switch_account(self, account_id: str):
        """
        Switches the active account to the account id provided.
        """
        request_data = APIRequest(body={"acctId": account_id})
        return request_data

    @request("GET", "portfolio/{account_id}/allocation")
    def account_allocation(self, account_id: str):
        """
        Information regarding the account's portfolio allocation by Asset Class, Industry and Category.
        """
        pass

    @request("GET", "portfolio/allocation")
    def aggregate_account_allocation(self, account_id_list: list[str]):
        """
        Returns the portfolio allocation for all accounts associated with the user.
        """
        request_data = APIRequest(
            body={
                "acctIds": account_id_list,
            }
        )
        return request_data

    @request("GET", "portfolio/{account_id}/positions/{page}")
    def account_positions_paginated(
        self,
        account_id: str,
        page: int = 0,
        mode: str = None,
        sort_column: str = None,
        sort_direction: str = None,
        pnl_period: str = None,
    ):
        """
        Returns a paginated list of positions for the given account id. Default page size is 30.
        """
        if sort_direction and sort_direction not in ["a", "d"]:
            raise ValueError(
                "sort_direction must be one of either ascending 'a' or descending 'd'"
            )
        request_data = APIRequest(
            params={
                "mode": mode,
                "sort": sort_column,
                "direction": sort_direction,
                "period": pnl_period,
            }
        )
        return request_data

    @request("GET", "portfolio/{account_id}/position/{conid}")
    def position_by_conid(self, account_id: str, conid: int):
        """
        Returns the position for the given account id and conid.
        """
        pass

    @request("POST", "portfolio/{account_id}/positions/invalidate")
    def invalidate_portfolio_cache(self, account_id: str):
        """
        Invalidates the backend portfolio cache for the given account id.
        """
        pass

    @request("GET", "portfolio/positions/{conid}")
    def aggregate_position_by_conid(self, conid: int):
        """
        Returns the aggregate position for the given conid across all accounts associated with the user.
        """
        pass


class GatewaySession(APISession):
    """
    Use this class to connect to the Client Portal API using the API Gateway.
    """

    def __init__(self, host: str = "localhost", port: int = 5000):
        self.__base_url = f"https://{host}:{port}/v1/api/"

    def __generate_request_url(self, endpoint: str) -> str:
        """
        Generate the full URL for the request.
        """
        return parse.urljoin(self.__base_url, endpoint)

    def make_api_request(self, method: str, endpoint: str, request_data: APIRequest):
        request_url = self.__generate_request_url(endpoint)
        response = requests.request(
            method,
            request_url,
            params=request_data.params,
            json=request_data.body,
            data=request_data.form_data,
            verify=False,
        )
        return response

    @request("GET", "sso/validate")
    def validate_session(self):
        """
        Validate the current session for the SSO user.
        """
        pass


class OAuthSession(APISession):
    """
    Use this class to connect to the Client Portal API using OAuth. You will need to provide
    a valid OAuthConfig object to the constructor to authenticate the session.
    """

    def __init__(
        self,
        oauth_config: OAuthConfig,
        live_session_token: str = None,
        live_session_token_expiry: str = None,
    ):
        self.__oauth_config = oauth_config
        self.encryption_key = read_private_key(self.__oauth_config.encryption_key_fp)
        self.signature_key = read_private_key(self.__oauth_config.signature_key_fp)
        self.consumer_key = self.__oauth_config.consumer_key
        self.access_token = self.__oauth_config.access_token
        self.access_token_secret = self.__oauth_config.access_token_secret
        self.dh_prime = self.__oauth_config.dh_prime
        self.realm = self.__oauth_config.realm
        self.live_session_token = live_session_token
        self.live_session_token_expiration = live_session_token_expiry
        self.base_url = "https://api.ibkr.com/v1/api/"

    def make_api_request(
        self,
        method: str,
        endpoint: str,
        request_data: APIRequest,
        encryption_method: str = "HMAC-SHA256",
        is_lst_request: bool = False,
    ):
        # If we don't have a valid live session token, request one, if LST request skip the LST check
        is_valid_lst = self.__is_valid_live_session_token()
        if not is_lst_request and not is_valid_lst:
            self.__request_live_session_token()
        request_url = self.__generate_request_url(endpoint)
        request_headers = self.__generate_request_headers(encryption_method)
        base_string = generate_base_string(
            method, request_url, request_headers, **dataclasses.asdict(request_data)
        )
        signature = self.__generate_request_signature(base_string, encryption_method)
        request_headers.update(request_data.extra_headers or {})
        request_headers["oauth_signature"] = signature
        logging.info(f"Request headers: {request_headers}")
        try:
            response = requests.request(
                method,
                request_url,
                headers={
                    "authorization": generate_authorization_header_string(
                        request_headers, self.realm
                    ),
                },
                params=request_data.params,
                json=request_data.body,
                data=request_data.form_data,
            )
            return response
        except Exception as e:
            logging.error(f"Error making request: {e}")

    def __request_live_session_token(self):
        """
        Get the live session token from the API. This token is used to sign subsequent requests to the API.
        """
        ENDPOINT = "oauth/live_session_token"
        REQUEST_METHOD = "POST"
        ENCRYPTION_METHOD = "RSA-SHA256"  # Only for this endpoint, in all other cases use HMAC-SHA256, which is the default.
        dh_random = generate_dh_random_bytes()
        dh_challenge = generate_dh_challenge(self.dh_prime, dh_random)
        prepend = calculate_live_session_token_prepend(
            self.access_token_secret, self.encryption_key
        )
        lst_extra_headers = {"diffie_hellman_challenge": dh_challenge}
        request_data = APIRequest(prepend=prepend, extra_headers=lst_extra_headers)
        response = self.make_api_request(
            REQUEST_METHOD,
            ENDPOINT,
            request_data,
            ENCRYPTION_METHOD,
            is_lst_request=True,
        )
        if not response.ok:
            raise Exception(f"Error getting live session token: {response.text}")
        response_data = response.json()
        dh_response = response_data["diffie_hellman_response"]
        lst_signature = response_data["live_session_token_signature"]
        lst_expiration = response_data["live_session_token_expiration"]
        lst = calculate_live_session_token(
            self.dh_prime, dh_random, dh_response, prepend
        )
        is_valid_lst = validate_live_session_token(
            lst, lst_signature, self.consumer_key
        )
        if not is_valid_lst:
            raise Exception("Error validating live session token")
        timestamp_in_seconds = lst_expiration / 1000
        human_readable_expiration = datetime.datetime.fromtimestamp(
            timestamp_in_seconds,
            datetime.timezone.utc,
        )
        print(
            f"Generated new live session token: {lst} with expiration: {lst_expiration} ({human_readable_expiration} UTC)"
        )
        self.live_session_token = lst
        self.live_session_token_expiration = lst_expiration

    def __generate_request_headers(
        self, signature_method: str = "HMAC-SHA256"
    ) -> dict[str, str]:
        oauth_nonce = generate_oauth_nonce()
        oauth_timestamp = self.__get_utc_timestamp()
        request_headers = {
            "oauth_consumer_key": self.consumer_key,
            "oauth_nonce": oauth_nonce,
            "oauth_signature_method": signature_method,
            "oauth_timestamp": str(int(oauth_timestamp)),
            "oauth_token": self.access_token,
        }
        return request_headers

    def __generate_request_url(self, endpoint: str) -> str:
        """
        Generate the full URL for the request.
        """
        url = parse.urljoin(self.base_url, endpoint)
        return url

    def __get_utc_timestamp(self) -> int:
        return int(datetime.datetime.utcnow().timestamp())

    def __is_valid_live_session_token(self):
        """
        Check if the live session token is valid.
        """
        if not self.live_session_token:
            return False
        if not self.live_session_token_expiration:
            return False
        current_timestamp = self.__get_utc_timestamp()
        is_expired = current_timestamp > int(self.live_session_token_expiration)
        if is_expired:
            return False
        return True

    def __generate_request_signature(self, base_string: str, encryption_method: str):
        """
        Generate the signature for the request.
        """
        if encryption_method == "RSA-SHA256":
            signature = generate_rsa_sha_256_signature(base_string, self.signature_key)
        else:
            signature = generate_hmac_sha_256_signature(
                base_string, self.live_session_token
            )
        return signature

    @request("POST", "iserver/auth/ssodh/init")
    def init_brokerage_session(self, compete: bool = True, publish: bool = True):
        """
        A brokerage session is required to access protected resources using the API. Protected resources include market
        data requests, position information, account performance. This endpoint needs to be called after requesting
        the live session token.
        """
        request_data = APIRequest(params={"compete": compete, "publish": publish})
        return request_data
