from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

def write_to_log(text_data):
    # Lấy thông tin về thời gian hiện tại
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Đọc nội dung hiện tại của tệp log.txt
    with open('log.txt', 'r') as log_file:
        existing_content = log_file.read()

    # Mở tệp log.txt với chế độ 'w' để ghi lại nội dung
    with open('log.txt', 'w') as log_file:
        # Ghi thông tin mới vào dòng đầu tiên
        log_file.write(f'{current_time}\n{text_data}\n')

        # Ghi lại nội dung hiện tại sau dòng mới
        log_file.write(existing_content)

@app.route('/api/save_text', methods=['POST'])
def save_text_to_file():
    try:
        # Lấy dữ liệu text từ request
        text_data = request.json['text']

        # Ghi vào tệp log.txt
        write_to_log(text_data)

        return jsonify({'message': 'POST text to API successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='192.168.43.107', port=5000)
