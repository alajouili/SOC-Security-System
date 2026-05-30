"""
Rate Limiter — Protection brute force via slowapi.
Fournit l'instance partagée du limiteur et des décorateurs réutilisables.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Instance partagée — importée dans main.py et les routes
limiter = Limiter(key_func=get_remote_address)