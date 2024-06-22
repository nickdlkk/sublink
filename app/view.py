from io import BytesIO

from flask import jsonify, render_template, send_file, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, create_refresh_token

from .node_parse import *
from .utils import get_address

blue = Blueprint('blue', __name__)
path = os.path.dirname(os.path.abspath(__file__))
subname_list = ['vless', 'vmess', 'ss', 'ssr', 'trojan', 'hysteria', 'hy2', 'hysteria2', 'http', 'https']


@blue.route('/sub/<string:target>/<path:name>', methods=['GET'])  # 订阅地址
def get_sub_url(target, name):
    ip_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    address = get_address(ip_address)
    timer = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    sub_log = SubLog(ip=ip_address, target=target, name=name, address=address, time=timer)
    try:
        db.session.add(sub_log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        db.session.flush()
        print('错误信息:' + str(e))
    if request.method == 'GET':
        name = decode_base64_if_emoji(name)
        subs = Sub.query.filter_by(name=name).all()
        # print(target, subs)
        if not subs:
            sub_log.status = 'error'
            sub_log.error = '订阅不存在'
            session_commie()
            return jsonify({
                'code': 400,
                'msg': '订阅不存在'
            })
        try:
            if target == 'clash':
                data = clash_encode(subs)
                response = make_response(
                    send_file(BytesIO(data.encode('utf-8')), mimetype='text/plain', as_attachment=False,
                              download_name=name))

                # 设置响应头
                # response.headers['subscription-userinfo'] = 'total=22333829939200;remarks=123123'
                sub_log.status = 'success'
                session_commie()
                return response
            if target == 'v2ray':
                data = []
                for sub in subs:
                    proxy_type = sub.node.split('://')[0]  # 节点类型
                    proxy_test = sub.node  # 节点信息
                    if proxy_type == 'http' or proxy_type == 'https':
                        url = proxy_test
                        response = requests.get(url)
                        text = decode_base64_if(response.text)
                        proxy_test = text
                    data.append(proxy_test)
                encoded_node = base64.b64encode('\n'.join(data).encode('utf-8')).decode('utf-8')
                response = make_response(
                    send_file(BytesIO(encoded_node.encode('utf-8')), mimetype='text/html', as_attachment=False,
                              download_name=f'{name}.txt'))
                # response.headers['subscription-userinfo'] = 'remarks=22333829939200;'
                return response
            if target == 'surge':
                interval = f'#!MANAGED-CONFIG {request.url} interval=86400 strict=false'  # 更新时间
                data = interval + '\n' + surge_encode(subs)
                response = make_response(
                    send_file(BytesIO(data.encode('utf-8')), mimetype='text/plain', as_attachment=False,
                              download_name=name))
                # response.headers['subscription-userinfo'] = 'remarks=22333829939200;'
                return response
        except Exception as e:
            sub_log.status = 'error'
            sub_log.error = str(e)
            session_commie()
            print(e)
            return ""


@blue.route('/clash_config', methods=['POST'])  # clash配置修改
@jwt_required()
def clash_config():
    if request.method == 'POST':
        data = request.get_json()
        index = data.get('index')
        # print(index)
        if index == 'read':
            with open(path + '/db/clash.yaml', 'r') as file:
                return jsonify({
                    'code': 200,
                    'msg': file.read()
                })
        if index == 'save':
            text = data.get('text')
            if text == '':
                return jsonify({
                    'code': 400,
                    'msg': '不能为空'
                })
            with open(path + '/db/clash.yaml', 'w') as file:
                file.write(text)
                return jsonify({
                    'code': 200,
                    'msg': '保存成功'
                })


@blue.route('/surge_config', methods=['POST'])  # surge配置修改
@jwt_required()
def surge_config():
    if request.method == 'POST':
        data = request.get_json()
        index = data.get('index')
        # print(index)
        if index == 'read':
            with open(path + '/db/surge.conf', 'r') as file:
                return jsonify({
                    'code': 200,
                    'msg': file.read()
                })
        if index == 'save':
            text = data.get('text')
            if text == '':
                return jsonify({
                    'code': 400,
                    'msg': '不能为空'
                })
            with open(path + '/db/surge.conf', 'w') as file:
                file.write(text)
                return jsonify({
                    'code': 200,
                    'msg': '保存成功'
                })


@blue.route('/')  # 前台程序
def get_index():
    return render_template('index.html')


@blue.route('/login', methods=['POST'])
def get_login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({
                'code': 404,
                'msg': '账号不存在'
            })
        if user.username == username and user.password == password:
            access_token = create_access_token(identity=username)
            refresh_token = create_refresh_token(identity=username)
            save_ip_address()  # 记录登录ip
            return jsonify({
                'code': 200,
                'token': access_token,
                'refresh': refresh_token,
                'msg': '登录成功'
            })
        else:
            return jsonify({
                'code': 404,
                'msg': '账号或者密码错误'
            })


@blue.route('/refresh', methods=['POST'])  # 刷新令牌
@jwt_required(refresh=True)
def get_refresh():
    if request.method == 'POST':
        current_user = get_jwt_identity()
        if current_user:
            token = create_access_token(current_user)
            return token
        else:
            return '没获取到'


@blue.route('/create_sub', methods=['POST'])  # 新建订阅
@jwt_required()
def get_create_sub():
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        nodes = data.get('node')
        # print(name,nodes)
        if Sub.query.filter_by(name=name).first():
            return jsonify({
                'code': 400,
                'msg': '订阅名字已经存在'
            })
        for i in nodes:
            if len(i.split('|')) >= 2:
                node = i.split('|')[0]
                remarks = i.split('|')[1]
            else:
                node = i
                remarks = ''
            found = any(keyword in node for keyword in subname_list)
            # print(found, node)
            if node != '' and found:
                sub = Sub(name=name, node=node, remarks=remarks)
                try:
                    db.session.add(sub)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    db.session.flush()
                    return jsonify({
                        'code': 400,
                        'msg': '错误信息：' + str(e)
                    })
        return jsonify({
            'code': 200,
            'msg': '创建成功'
        })
        # print('节点：' + node)
        # print('备注：' + remarks)


@blue.route('/create_node', methods=['POST'])  # 新建节点
@jwt_required()
def create_node():
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        remarks = data.get('remarks')
        node = data.get('node')
        found = any(keyword in node for keyword in subname_list)
        # print(node,found)
        if not found:
            return jsonify({
                'code': 400,
                'msg': '不是有效的协议,请检查后重新输入'
            })
        if node != '':
            sub = Sub(name=name, node=node, remarks=remarks)
            try:
                db.session.add(sub)
                db.session.commit()
                return jsonify({
                    'code': 200,
                    'msg': '创建成功'
                })
            except Exception as e:
                db.session.rollback()
                db.session.flush()
                return jsonify({
                    'code': 400,
                    'msg': '错误信息：' + str(e)
                })


@blue.route('/get_subs', methods=['POST'])  # 获取所有的订阅
@jwt_required()
def get_subs():
    if request.method == 'POST':
        subs = Sub.query.all()
        data = []
        for sub in subs:
            item = {
                'id': sub.id,
                'name': sub.name,
                'node': sub.node,
                'remarks': sub.remarks if sub.remarks != '' else '无备注'
            }
            data.append(item)
        return jsonify(data)


@blue.route('/rename_sub/<path:name>', methods=['POST'])  # 修改订阅名称
@jwt_required()
def rename_sub(name):
    if request.method == 'POST':
        subs = Sub.query.filter_by(name=name).all()
        data = request.get_json()
        newName = data.get('newName')
        if Sub.query.filter_by(name=newName).first():
            return jsonify({
                'code': 400,
                'msg': f'名字已存在'
            })
        for sub in subs:
            sub.name = newName
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                db.session.flush()
                return jsonify({
                    'code': 400,
                    'msg': f'错误{str(e)}'
                })
        return jsonify({
            'code': 200,
            'msg': '成功'
        })


@blue.route('/get_sub/<path:name>', methods=['POST'])  # 获取单个订阅
@jwt_required()
def get_sub(name):
    if request.method == 'POST':
        subs = Sub.query.filter_by(name=name).all()
        data = []
        for sub in subs:
            item = {
                'id': sub.id,
                'name': sub.name,
                'node': sub.node,
                'remarks': sub.remarks if sub.remarks != '' else 'null'
            }
            data.append(item)
        return jsonify(data)


@blue.route('/del_sub/<path:name>', methods=['POST'])  # 删除指定订阅
@jwt_required()
def del_sub(name):
    if request.method == 'POST':
        # print(name)
        subs = Sub.query.filter_by(name=name).all()
        # print(name,subs)
        if not subs:
            return jsonify({
                'code': 400,
                'msg': '不存在'
            })
        for sub in subs:
            try:
                db.session.delete(sub)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                db.session.flush()
                return jsonify({
                    'code': 400,
                    'msg': '错误信息:' + str(e)
                })
        return jsonify({
            'code': 200,
            'msg': '删除成功'
        })


@blue.route('/del_sub_node/<int:id>', methods=['POST'])  # 删除指定节点
@jwt_required()
def del_sub_node(id):
    if request.method == 'POST':
        sub = Sub.query.filter_by(id=id).first()
        if not Sub:
            return jsonify({
                'code': 400,
                'msg': '不存在'
            })
        try:
            db.session.delete(sub)
            db.session.commit()
            return jsonify({
                'code': 200,
                'msg': '删除成功'
            })
        except Exception as e:
            db.session.rollback()
            db.session.flush()
            return jsonify({
                'code': 400,
                'msg': '错误信息:' + str(e)
            })


@blue.route('/set_sub', methods=['POST'])  # 修改节点
@jwt_required()
def get_set_sub():
    remarks = ''
    newNode = ''
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        newNodes = data.get('newNode')
        subs = Sub.query.filter_by(name=name).all()
        for sub in subs:  # 删除表
            try:
                db.session.delete(sub)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                db.session.flush()
                return jsonify({
                    'code': 400,
                    'msg': '错误信息：' + str(e)
                })
        for i in newNodes:  # 创立表
            if len(i.split('|')) >= 2:
                newNode = i.split('|')[0]
                remarks = i.split('|')[1]
            else:
                newNode = i
                remarks = ''
            found = any(keyword in newNode for keyword in subname_list)
            if newNode != '' and found:
                sub = Sub(name=name, node=newNode, remarks=remarks)
                try:
                    db.session.add(sub)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    db.session.flush()
                    return jsonify({
                        'code': 400,
                        'msg': '错误信息：' + str(e)
                    })
        return jsonify({
            'code': 200,
            'msg': '修改成功'
        })


@blue.route('/set_node', methods=['POST'])  # 修改单个节点
@jwt_required()
def get_set_node():
    if request.method == 'POST':
        data = request.get_json()
        id = data.get('id')
        node = data.get('node')
        remarks = data.get('remarks')
        sub = Sub.query.filter_by(id=id).first()
        found = any(keyword in node for keyword in subname_list)
        if not found:
            return jsonify({
                'code': 400,
                'msg': '节点格式不对'
            })
        if sub:
            sub.node = node
            sub.remarks = remarks
            try:
                db.session.commit()
                return jsonify({
                    'code': 200,
                    'msg': '修改成功'
                })
            except Exception as e:
                db.session.rollback()
                db.session.flush()
                return jsonify({
                    'code': 400,
                    'msg': '错误信息：' + str(e)
                })


@blue.route('/set_user', methods=['POST'])  # 修改账号信息
@jwt_required()
def get_set_user():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        newUserName = data.get('newUserName')
        password = data.get('password')
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({
                'code': 400,
                'msg': '账号不正确'
            })
        user.username = newUserName
        user.password = password
        try:
            db.session.commit()
            return jsonify({
                'code': 200,
                'msg': '修改成功'
            })
        except Exception as e:
            db.session.rollback()
            db.session.flush()
            return jsonify({
                'code': 400,
                'msg': '错误信息:' + str(e)
            })


@blue.route('/decode_sub', methods=['POST'])  # 订阅解析
@jwt_required()
def decode_sub():
    if request.method == 'POST':
        data = request.get_json()
        urls = data.get('urls')
        datas = []
        for url in urls:
            response = requests.get(url)
            # print(response.status_code)
            if response.status_code == 200:
                print(decode_base64_if(response.text))
                datas.append(decode_base64_if(response.text))
            else:
                return jsonify({
                    'code': response.status_code,
                    'msg': response.text
                })
        return jsonify({
            'code': 200,
            'msg': datas
        })


@blue.route('/get_ip_address', methods=['POST'])  # 获取已经登录过的ip记录
@jwt_required()
def get_ip_address():
    if request.method == 'POST':
        logins = Login.query.order_by(Login.time.desc()).all()
        data = []
        for i in logins:
            login = {
                'id': i.id,
                'ip': i.ip,
                'address': i.address,
                'time': i.time
            }
            data.append(login)
        return jsonify(data)


@blue.route("/set_conifg", methods=['POST'])
@jwt_required()
def set_config():
    if request.method == 'POST':
        data = request.get_json()
        udp = data.get('udp')
        skipcert = data.get('skipcert')
        emoji = data.get('emoji')
        list = [('udp', udp), ('skipcert', skipcert), ('emoji', emoji)]
        for key, value in list:
            Config.query.filter_by(key=key).delete()
            config = Config(key=key, value=value)
            db.session.add(config)
        try:
            db.session.commit()
            global SkipCert, Udp, Emoji
            SkipCert = bool(skipcert)
            Udp = bool(udp)
            Emoji = bool(emoji)
            return jsonify({
                'code': 200,
                'msg': '设置保存成功'
            })
        except Exception as e:
            db.session.rollback()
            db.session.flush()
            return jsonify({
                'code': 400,
                'msg': '错误信息：' + str(e)
            })


@blue.route("/get_conifg", methods=['POST'])
@jwt_required()
def get_config():
    if request.method == 'POST':
        config = Config.query.all()
        data = {}
        global SkipCert, Udp, Emoji
        for i in config:
            data[i.key] = True if i.value == '1' else False
            if i.key == 'udp':
                Udp = True if i.value == '1' else False
            if i.key == 'emoji':
                Emoji = True if i.value == '1' else False
            if i.key == 'skipcert':
                SkipCert = True if i.value == '1' else False
        print(Udp, SkipCert, Emoji)
        return jsonify(data)


SkipCert = False
Udp = False
Emoji = False
