""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import requests
from connectors.core.connector import ConnectorError, get_logger
from .constants import *

logger = get_logger('oracle-access-manager')


class AccessManager(object):
    def __init__(self, config):
        self._server_url = config.get('host', '').strip('/')
        if not self._server_url.startswith('https://') and not self._server_url.startswith('http://'):
            self._server_url = 'https://' + self._server_url
        self._username = config.get('username')
        self._password = config.get('password')
        self._verify_ssl = config.get('verify_ssl') if config.get('verify_ssl') else False

    def make_rest_call(self, endpoint, method='GET', data=None, params=None, headers=None, files=None):
        try:
            service_endpoint = '{0}{1}'.format(self._server_url, endpoint)
            logger.info("Service URL: {0}".format(service_endpoint))
            response = requests.request(method, service_endpoint, headers=headers, data=data, params=params,
                                        verify=self._verify_ssl, files=files, auth=(self._username, self._password))
            try:
                from connectors.debug_utils.curl_script import make_curl
                import base64
                credentials = "{0}:{1}".format(self._username, self._password)
                encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
                headers['Authorization'] = 'Basic ' + encoded_credentials
                make_curl(method, endpoint, headers=headers, params=params, data=data, verify_ssl=self._verify_ssl)
            except Exception as err:
                logger.error(f"Error in curl utils: {str(err)}")
            logger.debug("API Response Status Code: {0}".format(response.status_code))
            logger.debug("API Response: {0}".format(response.text))
            if response.ok:
                return response.json()
            else:
                logger.error("{0}".format(response.text))
                raise ConnectorError("{0}".format(response.text))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(err)


def _check_health(config):
    param = {
        'pageSize': 1
    }
    retrieve_sessions(config, param)
    logger.info('connector available')
    return True


def retrieve_sessions(config, params):
    oam = AccessManager(config)
    payload = build_payload(params)
    return oam.make_rest_call(SESSION_ENDPOINT, method="POST", data=payload)


def delete_sessions(config, params):
    oam = AccessManager(config)
    payload = build_payload(params)
    return oam.make_rest_call(SESSION_ENDPOINT, method="DELETE", params=payload)


def get_user_status_by_user_id(config, params):
    oam = AccessManager(config)
    endpoint = USER_STATUS_RETRIEVER_ENDPOINT + str(params.get('userId'))
    return oam.make_rest_call(endpoint=endpoint, method="GET")


def change_user_status_by_user_id(config, params):
    oam = AccessManager(config)
    payload = build_payload(params)
    endpoint = USER_STATUS_CHANGER_ENDPOINT + str(params.pop('userId', ''))
    return oam.make_rest_call(endpoint=endpoint, method="PUT", data=payload)


def build_payload(params):
    data = {}
    for k, v in params.items():
        if isinstance(v, dict):
            data[k] = build_payload(v)
        elif v != "" or v is not None:
            data[k] = v
    return data


operations = {
    'retrieve_sessions': retrieve_sessions,
    'delete_sessions': delete_sessions,
    'get_user_status_by_user_id': get_user_status_by_user_id,
    'change_user_status_by_user_id': change_user_status_by_user_id
}
