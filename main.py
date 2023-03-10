import logging
import argparse

from logic import scan_sql_injection


if __name__ == "__main__":
    """
    Entry point to SQLmappy. Parses arguments, sets logging format and executes the tool.
    """

    # Uses argparse to parse the arguments provided for the tool.
    parser = argparse.ArgumentParser(prog='SQLmappy', description='Lightweight SQLmap tool.',
                                     epilog='Happy pen-testing!')
    parser.add_argument('-u', '--url', required=True, help='URL to pen-test on')
    parser.add_argument('-v', '--verbose', default=False, required=False, action='store_true', help='Verbose flag')
    args = parser.parse_args()

    # Sets logging format based on the provided arugments
    logging.basicConfig(format='%(asctime)s: [%(levelname)s] %(message)s',
                        level=logging.DEBUG if args.verbose else logging.WARNING)
    logging.debug("Executed argparse utility and set logging config")

    scan_sql_injection(url=args.url)
