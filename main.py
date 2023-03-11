import logging
import argparse

from logic import SQLInjection


if __name__ == "__main__":
    """
    Entry point to SQLmappy. Parses arguments, sets logging format and executes the tool.
    """

    # Uses argparse to parse the arguments provided for the tool.
    parser = argparse.ArgumentParser(prog='SQLmappy', description='Lightweight SQLmap tool.',
                                     epilog='Happy pen-testing!')
    parser.add_argument('-u', '--url', required=True, help='URL to pen-test on')
    parser.add_argument('-v', '--verbose', default=False, required=False, action='store_true', help='Verbose flag')

    attacks = parser.add_mutually_exclusive_group(required=True)
    attacks.add_argument('-e', '--error-based', action='store_true', help="Perform error-based SQL injection")
    attacks.add_argument('-t', '--time-based', action='store_true', help="Perform time-based SQL injection")

    args = parser.parse_args()


    # Sets logging format based on the provided arugments
    logging.basicConfig(format='%(asctime)s: [%(levelname)s] %(message)s',
                        level=logging.INFO if args.verbose else logging.WARNING)
    logging.info("Executed argparse utility and set logging config")

    # TODO: add parameters for injection types
    # ___________________________________________
    injection_types = ["error-based"]

    attack_object = SQLInjection(
        injection_type='error-based' if args.error_based else 'time-based',
        url=args.url
    )

    attack_object.attack()

    print(attack_object)
