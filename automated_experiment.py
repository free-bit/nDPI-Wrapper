#!/usr/bin/env python3
import requests
import argparse
import time
import random
from collections import Counter

GOOGLE = 'http://www.google.com'
FACEBOOK = 'http://www.facebook.com'
TWITTER = 'http://www.twitter.com'
INSTAGRAM = 'http://www.instagram.com'
HOTMAIL = 'http://www.hotmail.com'
GMAIL = 'http://www.gmail.com'
YOUTUBE = 'http://www.youtube.com'
TWITCH = 'http://www.twitch.tv'

CURRENT_APP = None

def send_req():
    # sends a request to app given at start of the program
    # returns 1 if gets a response, otherwise 0
    req = requests.get(CURRENT_APP)
    
    if req.status_code == 200:
        return 1
    else:
        return 0

def app_selector(app):
    return {
        'google': GOOGLE,
        'facebook': FACEBOOK,
        'twitter': TWITTER,
        'instagram': INSTAGRAM,
        'hotmail': HOTMAIL,
        'gmail': GMAIL,
        'youtube': YOUTUBE,
        'twitch': TWITCH
    }.get(app, None)

def arg_handler():
    parser = argparse.ArgumentParser(description = 'Sends given number of trials in a pseudorandom fashion to the given app')
    parser.add_argument("app", type = str)
    parser.add_argument("trials", type = int)
    args = parser.parse_args()

    if args.app and args.trials:
        global CURRENT_APP
        CURRENT_APP = app_selector(args.app)

        if not CURRENT_APP:
            print('Invalid app given!')
            return None
        else:
            print(CURRENT_APP)
        
        return args
    else:
        print('Arguments missing...')
        return None

def main():
    args = arg_handler()
    if not args:
        return

    results = []
    random.seed(35)

    for i in range(0, args.trials):
        try:
            retv = send_req()
            results.append(retv)
        except:
            print('Some exception')
            results.append[0]
        
        print(f'Trial {i+1}: {results[i]}')
        # wait for a random time between 0.5 and 1s
        time.sleep(0.5 + random.uniform(0, 0.5))

    ctr = Counter(results)
    succ_count = ctr[1]
    fail_count = ctr[0]

    print('Experiments done! The results is as follows:')
    print(f'Number of successful queries: {succ_count}')
    print(f'Number of failed queries: {fail_count}')
    
    

if __name__ == "__main__":
    main()