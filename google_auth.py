"""
pip install pyotp
ipython

help(pyotp)

"""
import pyotp

def getTOTPNOW(secret):
    m = pyotp.TOTP(secret)
    return m.now()