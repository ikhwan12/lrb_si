#!/usr/bin/env python

import re
import math

import certstream
import tqdm
import yaml
import time
import os
from Levenshtein import distance
from termcolor import colored, cprint
from tld import get_tld
from url_normalize import url_normalize
import signal

from confusables import unconfuse
from ai_engine import predict

import mysql.connector
import hashlib

mydb = mysql.connector.connect(host="localhost",user="root",password="",database="malicious_url")

certstream_url = 'wss://certstream.calidog.io'

log_unsafe = os.path.dirname(os.path.realpath(__file__))+'/unsafe_domains_'+time.strftime("%Y-%m-%d")+'.log'

log_suspicious = os.path.dirname(os.path.realpath(__file__))+'/suspicious_domains_'+time.strftime("%Y-%m-%d")+'.log'

suspicious_yaml = os.path.dirname(os.path.realpath(__file__))+'/suspicious.yaml'

external_yaml = os.path.dirname(os.path.realpath(__file__))+'/external.yaml'

pbar = tqdm.tqdm(desc='certificate_update', unit='cert')

def handler(signum, frame):
    print("URL is not respond")
    raise Exception("timeout")

def entropy(string):
    """Calculates the Shannon entropy of a string"""
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

def canonicalize(url):
    return url_normalize(url)

def sha256(url):
    sha_sign = hashlib.sha256(url.encode()).hexdigest()
    return sha_sign

def score_domain(domain):
    """Score `domain`.

    The highest score, the most probable `domain` is a phishing site.

    Args:
        domain (str): the domain to check.

    Returns:
        int: the score of `domain`.
    """
    score = 0
    for t in suspicious['tlds']:
        if domain.endswith(t):
            score += 20

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]

    # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com)
    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        domain = '.'.join([res.subdomain, res.domain])
    except Exception:
        pass

    # Higer entropy is kind of suspicious
    score += int(round(entropy(domain)*10))

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    domain = unconfuse(domain)

    words_in_domain = re.split("\W+", domain)

    # ie. detect fake .com (ie. *.com-account-management.info)
    if words_in_domain[0] in ['com', 'net', 'org']:
        score += 10

    # Testing keywords
    for word in suspicious['keywords']:
        if word in domain:
            score += suspicious['keywords'][word]

    # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
    for key in [k for (k,s) in suspicious['keywords'].items() if s >= 70]:
        # Removing too generic keywords (ie. mail.domain.com)
        for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
            if distance(str(word), str(key)) == 1:
                score += 70

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += domain.count('-') * 3

    # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
    if domain.count('.') >= 3:
        score += domain.count('.') * 3

    return score


def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            res = 1
            threat_level = ""
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(60)
            pbar.update(1)
            score = score_domain(domain.lower())

            # If issued from a free CA = more suspicious
            if "Let's Encrypt" in message['data']['chain'][0]['subject']['aggregated']:
                score += 10

            if score >= 100:
                threat_level = "Very High"
                tqdm.tqdm.write(
                    "[!] Suspicious: "
                    "{} (score={})".format(colored(domain, 'red', attrs=['underline', 'bold']), score))
                

            elif score >= 90:
                threat_level = "High"
                tqdm.tqdm.write(
                    "[!] Suspicious: "
                    "{} (score={})".format(colored(domain, 'red', attrs=['underline']), score))

            elif score >= 80:
                threat_level = "Medium"
                tqdm.tqdm.write(
                    "[!] Likely    : "
                    "{} (score={})".format(colored(domain, 'yellow', attrs=['underline']), score))

            elif score >= 65:
                threat_level = "Low"
                tqdm.tqdm.write(
                    "[+] Potential : "
                    "{} (score={})".format(colored(domain, attrs=['underline']), score))
                try:
                    res = predict(domain)
                except Exception as exc:
                    print(exc)
                    res = 2
                print('not safe') if res == 1 else print('safe')

            else :
                res = 0

            if res == 1:
                mycursor = mydb.cursor()
                url = canonicalize(domain)
                sql = "INSERT INTO url (url_name, threat_level, score) VALUES (%s, %s, %s)"
                val = (url, threat_level, score)
                mycursor.execute(sql, val)
                mydb.commit()
                print(mycursor.rowcount, "url table record inserted.")

                sql = "INSERT INTO hash_urls (url_hash, threat_level, score) VALUES (%s, %s, %s)"
                val = (sha256(url), threat_level, score)
                mycursor.execute(sql, val)
                mydb.commit()
                print(mycursor.rowcount, "hash_urls table record inserted.")

                with open(log_unsafe, 'a') as f:
                    f.write("{}\n".format(url))


if __name__ == '__main__':
    with open(suspicious_yaml, 'r') as f:
        suspicious = yaml.safe_load(f)

    with open(external_yaml, 'r') as f:
        external = yaml.safe_load(f)

    if external['override_suspicious.yaml'] is True:
        suspicious = external
    else:
        if external['keywords'] is not None:
            suspicious['keywords'].update(external['keywords'])

        if external['tlds'] is not None:
            suspicious['tlds'].update(external['tlds'])

    certstream.listen_for_events(callback, url=certstream_url)
