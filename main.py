import logging
import argparse

from logic import SQLInjection
from utilities import Injection

if __name__ == "__main__":
    """
    Entry point to SQLmappy. Parses arguments, sets logging format and executes the tool.
    """

    # Uses argparse to parse the arguments provided for the tool.
    parser = argparse.ArgumentParser(prog='SQLmappy', description='Lightweight SQLmap tool', epilog='Happy pen-testing!')
    parser.add_argument('-u', '--url', required=True, help='URL to pen-test on')
    parser.add_argument('-v', '--verbose', default=False, required=False, action='store_true', help='Verbose flag')
    parser.add_argument('-l', '--login-dvwa', default=False, required=False, action='store_true', help='login to DVWA server')
    parser.add_argument('-m', '--manual', default=False, required=False, action='store_true', help='Execute manual queries')
    parser.add_argument('-p', '--export-csv', required=False, help='Save the data into a file')

    attacks = parser.add_mutually_exclusive_group(required=True)
    attacks.add_argument('-e', '--error-based', action='store_true', help="Perform error-based SQL injection")
    attacks.add_argument('-b', '--boolean-based', action='store_true', help="Perform boolean-based SQL injection")

    args = parser.parse_args()

    # Sets logging format based on the provided arguments.
    logging.basicConfig(format='%(asctime)s: [%(levelname)s] %(message)s',
                        level=logging.INFO if args.verbose else logging.WARNING)
    logging.info("Executed argparse utility and set logging config")

    attack_object = SQLInjection(  # Initialize attack object with provided arguments.
        injection_type=Injection.ERROR_BASED if args.error_based else Injection.BOOLEAN_BASED,
        url=args.url,
        login_dvwa=args.login_dvwa,
        manual=args.manual,
        export_path=args.export_csv
    )

    # TODO: export csv

    # Performs attack on provided server.
    attack_object.attack()

    # Presents attack results.
    print(attack_object)
