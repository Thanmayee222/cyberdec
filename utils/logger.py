import logging

def get_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        # Log to a file
        file_handler = logging.FileHandler("honeypot.log")
        formatter = logging.Formatter('%(asctime)s | %(name)s | %(levelname)s | %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Optional: Also log to console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger
