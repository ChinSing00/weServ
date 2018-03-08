# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
import os

from flask import Flask, request, abort, render_template
from wechatpy import parse_message, create_reply
from wechatpy.utils import check_signature
from wechatpy.exceptions import (
    InvalidSignatureException,
    InvalidAppIdException,
)

# set token or get from environmentsp
TOKEN = os.getenv('WECHAT_TOKEN','WWWchinsing00COM')
AES_KEY = os.getenv('WECHAT_AES_KEY', 'cUQKxhR9UQIZeRVE7v4sWtE06KkgxmdJBEPwE5iqe6T')
APPID = os.getenv('WECHAT_APPID', 'wxbe46d941f0625426')

app = Flask(__name__)


@app.route('/')
def index():
    
    host = request.url_root
    return render_template('index.html', host=host)


@app.route('/wechat', methods=['GET','POST'])
def wechat():
    print('----------------start-----------------')
    signature = request.args.get('signature', '')
    timestamp = request.args.get('timestamp', '')
    nonce = request.args.get('nonce', '')
    encrypt_type = request.args.get('encrypt_type', 'raw')
    msg_signature = request.args.get('msg_signature', '')
    try:
        check_signature(TOKEN, signature, timestamp, nonce)
    except InvalidSignatureException:
        abort(403)
    if request.method == 'GET':
        echo_str = request.args.get('echostr', 'tttttttttttt')
        return echo_str
    

    # POST request
    if encrypt_type == 'raw':
        # plaintext mode
        msg = parse_message(request.data)
        if msg.type == 'text':
            reply = create_reply(msg.content, msg)
        else:
            reply = create_reply('Sorry, can not handle this for now', msg)
        return reply.render()
    else:
        # encryption mode
        from wechatpy.crypto import WeChatCrypto

        crypto = WeChatCrypto(TOKEN, AES_KEY, APPID)
        try:
            msg = crypto.decrypt_message(
                request.data,
                msg_signature,
                timestamp,
                nonce
            )
        except (InvalidSignatureException, InvalidAppIdException):
            abort(403)
        else:
            msg = parse_message(msg)
            if msg.type == 'text':
                reply = create_reply(msg.content, msg)
            else:
                reply = create_reply('Sorry, can not handle this for now', msg)
            return crypto.encrypt_message(reply.render(), nonce, timestamp)
@app.route('/test',methods=['GET','POST'])
def test():
    if request.method == 'GET':
        print('this is GET')
    elif request.method == 'POST':
        print('this is POST')    
    return request.method

if __name__ == '__main__':
    app.run('0.0.0.0',80, debug=True)
