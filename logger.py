import json, logging, time

def get_logger(path='logs/crypto.jsonl'):
    logger = logging.getLogger('crypto')
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(path, encoding='utf-8')
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                payload = {
                    'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'level': record.levelname,
                    'msg': record.getMessage(),
                }
                if hasattr(record, 'extra') and isinstance(record.extra, dict):
                    payload.update(record.extra)
                return json.dumps(payload, ensure_ascii=False)
        fh.setFormatter(JSONFormatter())
        logger.addHandler(fh)
    return logger
