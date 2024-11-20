from flask import Flask, request, jsonify, redirect, url_for
import bcrypt
import jwt
import datetime
import json
import os
from flask_cors import CORS
import secrets  # 用于生成随机密钥

app = Flask(__name__)
CORS(app)  # 允许跨域请求

# 配置类：用于储存密钥、文件路径等配置信息
class Config:
    SECRET_KEY = secrets.token_hex(16)  # 生成随机密钥 (16字节，32字符)
    USERS_FILE = 'users.json'
    FORCE_HTTPS = True  # 添加配置项，控制是否强制使用 HTTPS

app.config.from_object(Config)

# 强制重定向到 HTTPS
@app.before_request
def enforce_https():
    if app.config.get("FORCE_HTTPS", False):  # 检查是否启用 HTTPS 强制
        if request.headers.get("X-Forwarded-Proto", "http") != "https":  # 检查请求协议
            url = request.url.replace("http://", "https://", 1)  # 将 HTTP 重定向到 HTTPS
            return redirect(url, code=301)  # 301 永久重定向

# 定义根路径的路由
@app.route('/')
def home():
    return "Welcome to the API!"

# 帮助函数：读取用户数据
def read_users():
    if not os.path.exists(app.config['USERS_FILE']):
        return []
    with open(app.config['USERS_FILE'], 'r') as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            # 如果文件无法解析为 JSON，返回空列表
            return []

# 帮助函数：写入用户数据
def write_users(users):
    with open(app.config['USERS_FILE'], 'w') as file:
        json.dump(users, file, indent=2)

# 注册接口
@app.route('/register', methods=['POST'])
def register():
    # 检查是否是 JSON 请求
    if not request.is_json:
        return jsonify({"message": "Content-Type must be application/json"}), 415

    data = request.get_json()

    # 如果请求体为空，返回 400 错误
    if not data:
        return jsonify({"message": "Request body cannot be empty."}), 400

    # 提取用户数据
    username = data.get('username')
    password = data.get('password')

    # 提取基本信息
    basic_info = data.get('basic_info', {})
    age = basic_info.get('age', 0)
    gender = basic_info.get('gender', "string")
    medical_history = basic_info.get('medicalHistory', "string")
    family_history = basic_info.get('familyHistory', "string")

    # 检查是否提供了用户名和密码
    if not username or not password:
        return jsonify({'message': 'Username and password are required.'}), 400

    # 读取现有用户数据
    users = read_users()

    # 检查用户名是否已存在
    if any(user['username'] == username for user in users):
        return jsonify({'message': 'Username already exists.'}), 400

    # 哈希密码
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # 创建新用户
    new_user = {
        'username': username,
        'password': hashed_password,
        'basic_info': {
            'age': age,
            'gender': gender,
            'medicalHistory': medical_history,
            'familyHistory': family_history
        }
    }
    users.append(new_user)

    # 保存用户到文件
    write_users(users)

    return jsonify({'message': 'User registered successfully.'}), 201

# 登录接口
@app.route('/login', methods=['POST'])
def login():
    # 检查是否是 JSON 请求
    if not request.is_json:
        return jsonify({"message": "Content-Type must be application/json"}), 415

    data = request.get_json()

    # 如果请求体为空，返回 400 错误
    if not data:
        return jsonify({"message": "Request body cannot be empty."}), 400

    username = data.get('username')
    password = data.get('password')

    # 检查是否提供了用户名和密码
    if not username or not password:
        return jsonify({'message': 'Username and password are required.'}), 400

    # 读取现有用户数据
    users = read_users()
    user = next((u for u in users if u['username'] == username), None)

    # 检查用户是否存在
    if not user:
        return jsonify({'message': 'Invalid username or password.'}), 400

    # 验证密码
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'message': 'Invalid username or password.'}), 400

    # 生成 JWT Token
    token = jwt.encode({
        'username': user['username'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    # 如果 PyJWT 版本是 >= 2.0.0 ，你需要解码为字符串
    if isinstance(token, bytes):
        token = token.decode('utf-8')  # 将 token 转换为字符串

    return jsonify({'token': token})

# 受保护的接口：需要 token 验证
@app.route('/protected', methods=['GET'])
def protected():
    # 从请求头中获取 token
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'Token is required.'}), 401

    token = auth_header.split(' ')[1]

    try:
        # 验证 token，忽略 'typ' 字段（兼容性增强）
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'], options={"verify_aud": False})
        return jsonify({'message': f"Welcome, {decoded['username']}! You have access to protected data."})

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired.'}), 403

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token.'}), 403

# 测试接口
@app.route('/test', methods=['GET'])
def test():
    return "Flask is working!", 200

# 启动 Flask 应用
if __name__ == '__main__':
    app.run(host='172.36.209.7', port=8000, ssl_context=('cert.pem', 'key.pem'))