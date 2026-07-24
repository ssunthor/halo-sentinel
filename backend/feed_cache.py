import time

cache = {}
CACHE_DURATION = 600  # 10 minutes

def get_from_cache(key):
    if key in cache and time.time() - cache[key]['timestamp'] < CACHE_DURATION:
        return cache[key]['data']
    return None

def set_in_cache(key, data):
    cache[key] = {
        'timestamp': time.time(),
        'data': data
    }
