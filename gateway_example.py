from cpwebapi import session

# Initiate the gateway session
gateway_session = session.GatewaySession(host="localhost", port=5000)
# Call the authentication status endpoint and print response
authentication_status = gateway_session.auth_status()
print(authentication_status.json())
