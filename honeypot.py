# coding=utf-8
import subprocess
import re
import sys
from smtplib import SMTP_SSL as SMTP
from email.mime.text import MIMEText
import threading
from time import sleep


def honeypot():
    global ip1
    password = input(
        "Inserisci password : ")  # verificare l'interfaccia di rete - di solito è eth0 se è diversa sostituire eth0 nella riga successiva con l'interfaccia di rete corretta
    tcpdump = subprocess.Popen(
        "sudo tcpdump -tttt -q -l -i eth0 -n -s0 not vrrp and not stp and not arp and not net fe80::/16 and not ether host 01:00:0C:CC:CC:CC",
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    ip1 = "127.0.0.1"
    SMTPserver = ''  # inserire SMTPServer
    sender = ''  # inserire email del sender
    destination = ['']  # inserire email destinatario
    duplex = True
    USERNAME = ""  # inserire username SMTPserver  
    PASSWORD = password #durante l'inserimento della passw da terminale, in caso di errore è consigliabile scrivere la password tra doppi apici "password"

    while True:
        log = tcpdump.stdout.readline()

        if log:

            if "192.168.139.12.22" in log:  # modifica ip - inserire l'ip della macchina honeypot(tranne il .22 - bisogna lasciarlo perchè indica la porta 22)
                log_file = open('log.txt', 'a')
                log_file.write(log)
                log_file.close()
                print(log)
                ip = re.findall(pattern, log)[0]
                if ip != "192.168.139.12":  # inserire ip della macchina honeypot
                    if ip1 != ip:
                        ip1 = ip

                        text_subtype = 'plain'

                        content = """ Tentativo di Instrusione SSH Rilevato: """ + log
                        subject = "HoneyPot SSH ALERT"

                        try:
                            msg = MIMEText(content, text_subtype)
                            msg['Subject'] = subject
                            msg['From'] = sender

                            conn = SMTP(SMTPserver)
                            conn.set_debuglevel(False)
                            conn.login(USERNAME, PASSWORD)
                            try:
                                conn.sendmail(sender, destination, msg.as_string())
                            finally:
                                conn.quit()

                        except:
                            sys.exit("mail failed; %s" % "CUSTOM_ERROR")

                    timertorestart_th = threading.Thread(target=timertorestart)
                    timertorestart_th.start()

            if "ICMP" in log:
                log_file = open('log.txt', 'a')
                log_file.write(log)
                log_file.close()
                print(log)
                pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
                ip = re.findall(pattern, log)[0]

                if ip != "192.168.139.12":  # inserire ip della macchina honeypot
                    if ip1 != ip:
                        ip1 = ip
                        text_subtype = 'plain'

                        content = """ Tentativo di Instrusione ICMP(PING) Rilevato: """ + log

                        subject = "HoneyPot PING ALERT"

                        try:
                            msg = MIMEText(content, text_subtype)
                            msg['Subject'] = subject
                            msg['From'] = sender

                            conn = SMTP(SMTPserver)
                            conn.set_debuglevel(False)
                            conn.login(USERNAME, PASSWORD)
                            try:
                                conn.sendmail(sender, destination, msg.as_string())
                            finally:
                                conn.quit()

                        except:
                            sys.exit("mail failed; %s" % "CUSTOM_ERROR")

                        timertorestart_th = threading.Thread(target=timertorestart)
                        timertorestart_th.start()

def timertorestart():
    global ip1

    mytimer=50
    for x in range(50):
        mytimer = mytimer -1
        sleep(1)

    ip1 = "127.0.0.1"


if __name__ == "__main__":

    honeypot()
