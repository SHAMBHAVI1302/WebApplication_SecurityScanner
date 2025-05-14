from flask import Flask, render_template, request, jsonify
from zap_scan import zap_scan

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST','GET'])
def scan():
    target_url = request.form.get('url') 
    
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        scan_results = zap_scan(target_url)
        return render_template('results.html', results=scan_results, url=target_url)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
