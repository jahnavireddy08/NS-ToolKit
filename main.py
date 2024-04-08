import customtkinter as ctk
import socket

import banner_grabber,nmapscan,geoip,wifiscanner,packet_sniff


def nmap():
    window = ctk.CTkToplevel(app)
    window.title("Nmap Scanner")
    window.geometry("300x250")
    window.resizable(False, False)
    def domain():
        try:
            ans.insert('end', text="Scanning...\n\n")
            get = ctk.CTkInputDialog(text="Enter a domain: ", title="Nmap Scanner")
            target = socket.gethostbyname(get.get_input())
            out = nmapscan.scan(target)
            ans.insert('end', text=out + "\n\n")
        except Exception as e:
            ans.insert('end', text="Enter a valid domain.\n\n")

    def ipaddr():
        try:
            ans.insert('end', text="Scanning...\n\n")
            get = ctk.CTkInputDialog(text="Enter an IP: ", title="Nmap Scanner")
            target = get.get_input()
            out = nmapscan.scan(target)
            ans.insert('end', text=out + "\n\n")
        except Exception as e:
            ans.insert('end', text="Enter a valid IP.\n\n")

    dom = ctk.CTkButton(window, text="Enter a domain: ", command=domain)
    dom.place(x=150, y=50, anchor="center")
    ip = ctk.CTkButton(window, text="Enter an IP: ", command=ipaddr)
    ip.place(x=150, y=100, anchor="center")


def banner_grab():
    window = ctk.CTkToplevel(app)
    window.title("Banner Grabber")
    window.geometry("300x250")
    window.resizable(False, False)

    def domain():
        try:
            ans.insert('end', text="Grabbing banner...\n\n")
            get0 = ctk.CTkInputDialog(text="Enter a url: ", title="Banner Grabber")
            url = socket.gethostbyname(get0.get_input())
            get1 = ctk.CTkInputDialog(text="Enter a port: ", title="Banner Grabber")
            port = get1.get_input()
            out = banner_grabber.banner_grabber(url, int(port))
            ans.insert('end', text=out + "\n\n")
        except Exception as e:
            ans.insert('end', text="Enter a valid url and port.\n\n")

    def ipaddr():
        try:
            ans.insert('end', text="Grabbing banner...\n\n")
            get0 = ctk.CTkInputDialog(text="Enter an IP: ", title="Banner Grabber")
            ip = get0.get_input()
            get1 = ctk.CTkInputDialog(text="Enter a port: ", title="Banner Grabber")
            port = get1.get_input()
            out = banner_grabber.banner_grabber(ip, int(port))
            ans.insert('end', text=out + "\n\n")
        except Exception as e:
            ans.insert('end', text="Enter a valid ip and port.\n\n")

    dom = ctk.CTkButton(window, text="Enter a domain: ", command=domain)
    dom.place(x=150, y=100, anchor="center")
    ip = ctk.CTkButton(window, text="Enter an IP: ", command=ipaddr)
    ip.place(x=150, y=150, anchor="center")


def locate():
    window = ctk.CTkToplevel(app)
    window.title("GeoIP")
    window.geometry("300x250")
    window.resizable(False, False)

    def domain():
        try:
            ans.insert('end', text="Locating...\n\n")
            get = ctk.CTkInputDialog(text="Enter a url: ", title="GeoIP")
            url = get.get_input()
            out = geoip.get_loc(url)
            ans.insert('end', text=out + "\n\n")

        except Exception as e:
            ans.insert('end', text="Please enter a valid url.\n\n")


    dom = ctk.CTkButton(window, text="GeoIP ", command=domain)
    dom.place(x=150, y=200, anchor="center")


def wifiscan():
    window = ctk.CTkToplevel(app)
    window.title("Wifi Scanner")
    window.geometry("300x250")
    window.resizable(False, False)

    def domain():
        try:
            ans.insert('end', text="Scanning...\n\n")
            out = wifiscanner.wifi(range.get())
            ans.insert('end', text=out + "\n\n")
        except Exception as e:
            ans.insert('end', text="Please enter a valid ip range.\n\n")

    iplabel = ctk.CTkLabel(window, text="Enter a ip range: ")
    iplabel.place(x=150, y=50, anchor="center")
    range = ctk.CTkEntry(window, placeholder_text="192.168.155.0/24", width=200)
    range.place(x=150, y=100, anchor="center")
    dom = ctk.CTkButton(window, text="Wifi Scanner", command=domain)
    dom.place(x=150, y=150, anchor="center")


def sniff():
    window = ctk.CTkToplevel(app)
    window.title("Packet Sniffer")
    window.geometry("300x250")
    window.resizable(False, False)

    def domain():
        try:
            ans.insert('end', "Sniffing...\n\n")
            out = packet_sniff.packet(int(count.get()))
            ans.insert('end', text=out + "\n\n")
        except Exception as e:
            ans.insert('end', text="Please enter a valid number.\n\n")

    countlabel = ctk.CTkLabel(window, text="Enter the number of packets to be sniffed: ")
    countlabel.place(x=150, y=50, anchor="center")
    count = ctk.CTkEntry(window, placeholder_text="Enter a number", width=200)
    count.place(x=150, y=100, anchor="center")
    dom = ctk.CTkButton(window, text="Packet Sniffer", command=domain)
    dom.place(x=150, y=150, anchor="center")
    
ctk.set_appearance_mode("Light")
#ctk.set_default_color_theme("Night_Purple.json")

app = ctk.CTk()
app.geometry("720x720")
app.resizable(False, False)

app.title("NS Toolkit")

title = ctk.CTkLabel(app, text="Choose an Option: ", font=("Baskerville Old Face", 25))
title.place(x=350, y=100, anchor="center")

nmaps = ctk.CTkButton(app, text="Nmap Scan", command=nmap , fg_color= 'Blue')
nmaps.place(x=350, y=150, anchor="center")

ban = ctk.CTkButton(app, text="Banner Grabber", command=banner_grab ,fg_color= 'Yellow',text_color='Black')
ban.place(x=350, y=200, anchor="center")

loc = ctk.CTkButton(app, text="Geolocation", command=locate,fg_color= 'Green')
loc.place(x=350, y=250, anchor="center")

wifi = ctk.CTkButton(app, text="Wifi Scanner", command=wifiscan)
wifi.place(x=350, y=300, anchor="center")

pack = ctk.CTkButton(app, text="Packet Sniffer", command=sniff , fg_color= 'Blue')
pack.place(x=350, y=350, anchor="center")

output = ctk.CTkLabel(app, text="Output: ", font=("Century Gothic", 15))
output.place(x=350, y=400, anchor="center")

ans = ctk.CTkTextbox(app, width=500, height=200, )
ans.place(x=350, y=475, anchor="center")

quit = ctk.CTkButton(app, text="Quit Toolkit", command=app.quit , fg_color= 'Red')
quit.place(x=350, y=650, anchor="center")

app.mainloop()