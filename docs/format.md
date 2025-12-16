# Формат контейнерів

## AES-GCM (*.gcm)
Файл містить заголовок JSON (1 рядок), потім `\n`, потім ciphertext bytes.
Заголовок: mode, nonce (b64), tag (b64), key_label, key_version, salt (b64).

## AES-CBC+HMAC (*.cbc)
Заголовок JSON (1 рядок), потім `\n`, потім ciphertext bytes.
Заголовок: mode, iv (b64), hmac (b64), key_label, key_version, salt (b64).

## Hybrid (*.hybr)
Заголовок JSON (1 рядок), потім `\n`, потім ciphertext bytes.
Заголовок: mode (gcm/cbc), enc_key (RSA-OAEP, b64), nonce/iv, tag/hmac, key_bytes_len.
