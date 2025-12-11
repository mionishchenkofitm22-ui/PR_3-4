# ПР №3-4. Реалізація симетричного/асиметричного шифрування

> Це **поради**, а не інструкція. Можливі неточності; перевіряйте офіційну документацію та політики.

## Вимоги
- Python 3.10+
- `pip install -r requirements.txt`

## Швидкий старт
```bash
# 1) Симетрія: створити ключ і зашифрувати/розшифрувати файл (GCM)
python cli.py sym new --label default
python cli.py sym enc --label default --in data/sample.txt --out outputs/sample.gcm --mode gcm
python cli.py sym dec --label default --in outputs/sample.gcm --out outputs/sample.dec

# 2) RSA: згенерувати ключі, підписати та перевірити
python cli.py rsa gen --priv keys/priv.pem --pub keys/pub.pem --password changeit --bits 3072
python cli.py rsa sign --priv keys/priv.pem --password changeit --in data/sample.txt --sig outputs/sample.sig
python cli.py rsa verify --pub keys/pub.pem --in data/sample.txt --sig outputs/sample.sig

# 3) Гібрид: шифрувати AES‑ключ RSA‑OAEP + дані AES‑GCM
python cli.py hybrid enc --pub keys/pub.pem --in data/sample.txt --out outputs/sample.hybr
python cli.py hybrid dec --priv keys/priv.pem --password changeit --in outputs/sample.hybr --out outputs/sample.hybr.dec

# 4) Бенчмарки
python cli.py bench --sizes 1MB 10MB --modes gcm cbc --rsa-bits 2048 3072 4096
```
