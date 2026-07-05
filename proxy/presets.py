"""
Fake TLS (SNI) presets.

The Fake-TLS MTProto inbound masks itself as a TLS server for a chosen domain.
The domain should be a real HTTPS site that supports TLS 1.3 and is reachable
(not blocked) from the client's network, so the masking looks legitimate.

  * RU       — popular sites usually reachable inside Russia.
  * FOREIGN  — global CDNs/sites, good when an external SNI is preferred.
"""

FAKE_TLS_PRESETS = {
    'ru': [
        'dzen.ru',
        'vk.com',
        'ok.ru',
        'mail.ru',
        'gosuslugi.ru',
        'avito.ru',
        'ozon.ru',
        'kinopoisk.ru',
    ],
    'foreign': [
        'www.cloudflare.com',
        'www.microsoft.com',
        'www.google.com',
        'aws.amazon.com',
        'www.apple.com',
        'dl.google.com',
        'www.bing.com',
        'www.tradingview.com',
    ],
}

PRESET_LABELS = {
    'ru': 'RU-сайты (для России)',
    'foreign': 'Зарубежные сайты / CDN',
}
