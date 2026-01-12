from flask import request, send_file
from flask import Flask, render_template, send_file
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from wtforms.validators import InputRequired
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from io import BytesIO
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'static/files'

AES_KEY = b'16byteslongkey!!'  # MUST be 16 bytes


class UploadFileForm(FlaskForm):
    file = FileField("File", validators=[InputRequired()])
    submit = SubmitField("Upload File")


def encrypt_file(data):
    cipher = AES.new(AES_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext


def decrypt_file(encrypted_data):
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


@app.route('/', methods=['GET', 'POST'])
def home():
    form = UploadFileForm()

    if form.validate_on_submit():
        file = form.file.data
        file_data = file.read()

        encrypted_data = encrypt_file(file_data)

        upload_path = os.path.join(
            os.path.abspath(os.path.dirname(__file__)),
            app.config['UPLOAD_FOLDER']
        )
        os.makedirs(upload_path, exist_ok=True)

        encrypted_filename = secure_filename(file.filename) + ".enc"

        with open(os.path.join(upload_path, encrypted_filename), "wb") as f:
            f.write(encrypted_data)

        return render_template("index.html", form=form, filename=encrypted_filename)


    return render_template('index.html', form=form)


@app.route('/download', methods=['GET'])
def download():
    filename = request.args.get('filename')
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists(file_path):
        return "File not found", 404

    return send_file(file_path, as_attachment=True)


@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_file(encrypted_data)

    return send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=filename.replace(".enc", "")
    )


if __name__ == '__main__':
    app.run(debug=True)
