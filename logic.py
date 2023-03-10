import logging
import re
import json

import requests
from prettytable import PrettyTable

from typing import Generator, Union

from utilities import log
from urllib.parse import quote_plus

PAYLOADS = json.load(open("payloads.json"))


class AttackFinishedException(Exception):
    pass

class Attack:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url

    def run_payload(self, payload):
        attack_url: str = f"{self.base_url}{quote_plus(payload)}"
        response = self.session.get(attack_url)
        return attack_url, response

    # def get_payloads(self, injection_type: str) -> Generator[str, str, None]:
    #     payloads = json.load(open("payloads.json"))
    #     for payload in payloads[injection_type]:
    #         yield payload['payload'], payload['vector']  # TODO change this to exploit
    #
    # def run_payloads(self, injection_type: str) -> requests.Response:
    #     for payload, exploit in self.get_payloads(injection_type):
    #         attack_url: str = f"{self.base_url}{quote_plus(payload)}"
    #         response = self.session.get(attack_url)
    #         yield attack_url, payload, exploit, response


class ErrorBasedAttack(Attack):
    def __init__(self, session, base_url):
        super().__init__(session, base_url)
        self._description: str = "Error-based SQL injection"

        error_based = PAYLOADS["error-based"]
        self.error_patterns = error_based["error_patterns"]
        self.extractors = error_based["extractors"]
        self.injections = error_based["injections"]

    def iterate_injections(self):
        for injection in self.injections:
            yield injection["title"], injection["detect"], injection["exploit"]

    def get_all_databases(self, exploit_query):
        logging.info("Attempting to fetch databases count...")


    def exploit(self, exploit_query):
        self.get_all_databases()

    def detect(self):
        # for attack_url, payload, exploit, response in self.run_payloads("error-based"):
        #     error_response = self._get_mysql_error(response=response)
        #     if not error_response:
        #         continue
        #
        #     logging.critical(f"Detected error-based injection with URL {attack_url}");

        for title, detect_query, exploit_query in self.iterate_injections():
            attack_url, response = self.run_payload(detect_query)
            error_response = self._get_mysql_error(response=response)
            if not error_response:
                continue

            logging.critical(f"Detected error-based injection {title} with URL {attack_url}")
            self.exploit(exploit_query)

        return []

    def attack(self):
        try:
            self.detect()
            logging.info("Couldn't find Error-based attacks!")
        except AttackFinishedException as e:
            logging.info("Finished Error-based attack successfully!")


    def _get_mysql_error(self, response) -> Union[None, str]:
        _content = response.content.decode().lower()  # Extracted content from response object.

        for _error in self.error_patterns:
            match = re.search(_error, _content)
            if match:
                return match.group("error_response")
        return None


class TimeBasedAttack(Attack):
    def __init__(self, session, base_url):
        super().__init__(session, base_url)
        self._description: str = "Time-based SQL injection"

    def detect(self):
        for attack_url, payload, response in self.run_payloads("error-based"):
            pass
            # if self._is_mysql_error(response=response):
            #     logging.critical(f"Detected error-based injection with URL {attack_url}")
            #     yield ['error-based', self._description, payload]


# Supported injection types.
INJECTION_TYPES = {
    "error-based": ErrorBasedAttack,
    # "time-based": TimeBasedAttack
}


class SQLInjection:
    """
    TODO: Document this class.
    """

    def __init__(self, injection_types: list, url: str) -> None:
        """
        TODO: document this.
        @param injection_types:
        @param url:
        @return: None.
        """

        # Initialize HTTP session.
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, " \
                                             "like Gecko) Chrome/83.0.4103.106 Safari/537.36 "

        # Initialize needed fields
        self._injection_types = injection_types
        self._url = url
        self._detected_vulnerabilities = PrettyTable(['Type', 'Description', 'Payload'])
        self._detected_exploits = PrettyTable(['Type', 'Description', 'Payload'])

        self._potential_exploits = []

        # TODO The following code is for testing purposes.
        login_payload = {
            "username": "admin",
            "password": "password",
            "Login": "Login",
        }
        login_url = "http://172.19.217.41/login.php"
        r = self.session.get(login_url)
        token = re.search("user_token'\s*value='(.*?)'", r.text).group(1)
        login_payload['user_token'] = token
        self.session.post(login_url, data=login_payload)

    @log
    def attack(self) -> None:
        """
        TODO: Document this.
        @return:
        """

        # Iterare over required injection types.
        for injection_type in self._injection_types:
            injection_class = INJECTION_TYPES[injection_type]

            # Detect injection_type vulnerabilities.
            detector = injection_class(self.session, self._url)
            for vulnerability in detector.detect():
                # self._potential_exploits += vulnerability[:3] + vulnerability[4:]  # Save relevant exploit
                self._detected_vulnerabilities.add_row(vulnerability[:-1])
                # detector.exploit()

    def __str__(self) -> str:
        """
        String representation of SQLInjection object.
        @return: String representation.
        """

        return str(self._detected_vulnerabilities)

    def __repr__(self) -> str:
        """
        String representation of SQLInjection object.
        @return: String representation.
        """

        return str(self._detected_vulnerabilities)
