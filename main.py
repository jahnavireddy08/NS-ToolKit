from kivy.app import App
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout

import socket
import banner_grabber
import nmapscan
import geoip
import wifiscanner
import packet_sniff

class NSApp(App):
    def build(self):
        self.title = "NS Toolkit"
        layout = GridLayout(cols=2)

        layout.add_widget(Button(text="Nmap Scan", on_press=self.nmap))
        layout.add_widget(Button(text="Banner Grabber", on_press=self.banner_grab))
        layout.add_widget(Button(text="Geolocation", on_press=self.locate))
        layout.add_widget(Button(text="Wifi Scanner", on_press=self.wifiscan))
        layout.add_widget(Button(text="Packet Sniffer", on_press=self.sniff))

        self.output_label = Label(text="Output: ")
        layout.add_widget(self.output_label)

        self.ans_label = Label(text="")
        layout.add_widget(self.ans_label)

        return layout

    def nmap(self, instance):
        content = BoxLayout(orientation='vertical')
        self.popup = Popup(title="Nmap Scanner", content=content, size_hint=(None, None), size=(300, 250))

        domain_button = Button(text="Enter a domain")
        domain_button.bind(on_press=self.domain_scan)
        content.add_widget(domain_button)

        ip_button = Button(text="Enter an IP")
        ip_button.bind(on_press=self.ip_scan)
        content.add_widget(ip_button)

        self.popup.open()

    def domain_scan(self, instance):
        content = BoxLayout(orientation='vertical')
        self.popup.dismiss()
        domain_popup = Popup(title="Enter a domain", content=content, size_hint=(None, None), size=(300, 250))

        self.domain_input = TextInput()
        content.add_widget(self.domain_input)

        scan_button = Button(text="Scan")
        scan_button.bind(on_press=self.perform_domain_scan)
        content.add_widget(scan_button)

        domain_popup.open()

    def perform_domain_scan(self, instance):
        try:
            target = socket.gethostbyname(self.domain_input.text)
            out = nmapscan.scan(target)
            self.ans_label.text = out
        except Exception as e:
            self.ans_label.text = "Enter a valid domain."

    def ip_scan(self, instance):
        content = BoxLayout(orientation='vertical')
        self.popup.dismiss()
        ip_popup = Popup(title="Enter an IP", content=content, size_hint=(None, None), size=(300, 250))

        self.ip_input = TextInput()
        content.add_widget(self.ip_input)

        scan_button = Button(text="Scan")
        scan_button.bind(on_press=self.perform_ip_scan)
        content.add_widget(scan_button)

        ip_popup.open()

    def perform_ip_scan(self, instance):
        try:
            out = nmapscan.scan(self.ip_input.text)
            self.ans_label.text = out
        except Exception as e:
            self.ans_label.text = "Enter a valid IP."

    def banner_grab(self, instance):
        content = BoxLayout(orientation='vertical')
        self.popup = Popup(title="Banner Grabber", content=content, size_hint=(None, None), size=(300, 250))

        domain_button = Button(text="Enter a URL")
        domain_button.bind(on_press=self.domain_grab)
        content.add_widget(domain_button)

        ip_button = Button(text="Enter an IP")
        ip_button.bind(on_press=self.ip_grab)
        content.add_widget(ip_button)

        self.popup.open()

    def domain_grab(self, instance):
        content = BoxLayout(orientation='vertical')
        self.popup.dismiss()
        domain_popup = Popup(title="Enter a URL", content=content, size_hint=(None, None), size=(300, 250))

        self.domain_input = TextInput()
        content.add_widget(self.domain_input)

        port_input = TextInput(hint_text="Enter a port")
        content.add_widget(port_input)

        grab_button = Button(text="Grab")
        grab_button.bind(on_press=lambda instance: self.perform_domain_grab(self.domain_input.text, port_input.text))
        content.add_widget(grab_button)

        domain_popup.open()

    def perform_domain_grab(self, url, port):
        try:
            ip = socket.gethostbyname(url)
            out = banner_grabber.banner_grabber(ip, int(port))
            self.ans_label.text = out
        except Exception as e:
            self.ans_label.text = "Enter a valid URL and port."

    def ip_grab(self, instance):
        content = BoxLayout(orientation='vertical')
        self.popup.dismiss()
        ip_popup = Popup(title="Enter an IP", content=content, size_hint=(None, None), size=(300, 250))

        self.ip_input = TextInput()
        content.add_widget(self.ip_input)

        port_input = TextInput(hint_text="Enter a port")
        content.add_widget(port_input)

        grab_button = Button(text="Grab")
        grab_button.bind(on_press=lambda instance: self.perform_ip_grab(self.ip_input.text, port_input.text))
        content.add_widget(grab_button)

        ip_popup.open()

    def perform_ip_grab(self, ip, port):
        try:
            out = banner_grabber.banner_grabber(ip, int(port))
            self.ans_label.text = out
        except Exception as e:
            self.ans_label.text = "Enter a valid IP and port."

    def locate(self, instance):
        content = BoxLayout(orientation='vertical')
        self.popup = Popup(title="GeoIP", content=content, size_hint=(None, None), size=(300, 250))

        domain_button = Button(text="GeoIP")
        domain_button.bind(on_press=self.perform_locate)
        content.add_widget(domain_button)

        self.popup.open()

    def perform_locate(self, instance):
        content = BoxLayout(orientation='vertical')
        self.popup.dismiss()
        locate_popup = Popup(title="GeoIP", content=content, size_hint=(None, None), size=(300, 250))

        self.domain_input = TextInput()
        content.add_widget(self.domain_input)

        locate_button = Button(text="Locate")
        locate_button.bind(on_press=lambda instance: self.perform_geoip(self.domain_input.text))
        content.add_widget(locate_button)

        locate_popup.open()

    def perform_geoip(self, url):
        try:
            out = geoip.get_loc(url)
            self.ans_label.text = out
        except Exception as e:
            self.ans_label.text = "Please enter a valid URL."

    def wifiscan(self, instance):
        content = BoxLayout(orientation='vertical')
        self.popup = Popup(title="Wifi Scanner", content=content, size_hint=(None, None), size=(300, 250))

        range_input = TextInput(hint_text="Enter an IP range")
        content.add_widget(range_input)

        scan_button = Button(text="Scan")
        scan_button.bind(on_press=lambda instance: self.perform_wifiscan(range_input.text))
        content.add_widget(scan_button)

        self.popup.open()

    def perform_wifiscan(self, ip_range):
        try:
            out = wifiscanner.wifi(ip_range)
            self.ans_label.text = out
        except Exception as e:
            self.ans_label.text = "Please enter a valid IP range."

    def sniff(self, instance):
        content = BoxLayout(orientation='vertical')
        self.popup = Popup(title="Packet Sniffer", content=content, size_hint=(None, None), size=(300, 250))

        count_input = TextInput(hint_text="Enter the number of packets to be sniffed")
        content.add_widget(count_input)

        sniff_button = Button(text="Sniff")
        sniff_button.bind(on_press=lambda instance: self.perform_sniff(count_input.text))
        content.add_widget(sniff_button)

        self.popup.open()

    def perform_sniff(self, count):
        try:
            out = packet_sniff.packet(int(count))
            self.ans_label.text = out
        except Exception as e:
            self.ans_label.text = "Please enter a valid number."


if __name__ == '__main__':
    NSApp().run()
