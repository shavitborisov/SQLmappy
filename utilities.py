import logging


def log(func: any) -> any:
    """
    Logging decorator to track executed function. Used for debugging.
    @param func: The decorated function.
    @return: Function func's result.
    """

    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        logging.info("Executed " + func.__name__)
        return result

    return wrapper
