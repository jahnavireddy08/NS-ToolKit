from flask import Flask, render_template, request
import socket
import banner_grabber
import nmapscan
import geoip
import wifiscanner
import packet_sniff

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', background_color='#f0f0f0', font_style='Arial, sans-serif')

@app.route('/nmap', methods=['GET', 'POST'])
def nmap():
    if request.method == 'POST':
        try:
            target = request.form['target']
            if target:
                output = nmapscan.scan(socket.gethostbyname(target))
            else:
                output = "Please enter a valid domain or IP."
        except Exception as e:
            output = f"Error: {str(e)}"
        return render_template('nmap.html', output=output, background_color='#f0f0f0', font_style='Arial, sans-serif')
    return render_template('nmap.html', background_color='#f0f0f0', font_style='Arial, sans-serif')

@app.route('/banner_grab', methods=['GET', 'POST'])
def banner_grab():
    if request.method == 'POST':
        try:
            target = request.form['target']
            port = int(request.form['port'])
            if target and port:
                output = banner_grabber.banner_grabber(target, port)
            else:
                output = "Please enter a valid URL and port."
        except Exception as e:
            output = f"Error: {str(e)}"
        return render_template('banner_grab.html', output=output, background_color='#f0f0f0', font_style='Arial, sans-serif')
    return render_template('banner_grab.html', background_color='#f0f0f0', font_style='Arial, sans-serif')

@app.route('/geoip', methods=['GET', 'POST'])
def geoip():
    if request.method == 'POST':
        try:
            url = request.form['url']
            if url:
                output = geoip.get_loc(url)
            else:
                output = "Please enter a valid URL."
        except Exception as e:
            output = f"Error: {str(e)}"
        return render_template('geoip.html', output=output, background_color='#f0f0f0', font_style='Arial, sans-serif')
    return render_template('geoip.html', background_color='#f0f0f0', font_style='Arial, sans-serif')

@app.route('/wifiscan', methods=['GET', 'POST'])
def wifiscan():
    if request.method == 'POST':
        try:
            ip_range = request.form['ip_range']
            if ip_range:
                output = wifiscanner.wifi(ip_range)
            else:
                output = "Please enter a valid IP range."
        except Exception as e:
            output = f"Error: {str(e)}"
        return render_template('wifiscan.html', output=output, background_color='#f0f0f0', font_style='Arial, sans-serif')
    return render_template('wifiscan.html', background_color='#f0f0f0', font_style='Arial, sans-serif')

@app.route('/sniff', methods=['GET', 'POST'])
def sniff():
    if request.method == 'POST':
        try:
            count = int(request.form['count'])
            if count:
                output = packet_sniff.packet(count)
            else:
                output = "Please enter a valid packet count."
        except Exception as e:
            output = f"Error: {str(e)}"
        return render_template('sniff.html', output=output, background_color='#f0f0f0', font_style='Arial, sans-serif')
    return render_template('sniff.html', background_color='#f0f0f0', font_style='Arial, sans-serif')

if __name__ == '__main__':
    app.run(debug=True)
