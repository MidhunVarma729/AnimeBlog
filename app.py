from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import smtplib
from dotenv import load_dotenv
import os

load_dotenv()

my_mail = os.getenv('MY_MAIL')
my_password = os.getenv('MY_PASSWORD')
to_mail = os.getenv('TO_MAIL')

def send_mail(username, message, phone, email):
    message = f'Subject: New message from your blog\n\nUsername: {username}\nPhone: {phone}\nMessage: {message}\nE-mail:{email}'.encode(
        'utf-8', 'ignore').decode('utf-8')
    with smtplib.SMTP('smtp.mail.yahoo.com') as connection:
        connection.starttls()
        connection.login(my_mail, my_password)
        connection.sendmail(from_addr=my_mail, to_addrs=to_mail, msg=message)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    user_blog_posts = relationship("BlogPost", back_populates="author")
    user_comments =  relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    author = relationship("User", back_populates="user_blog_posts")
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key = True)
# user relationship 
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    comment_author = relationship("User", back_populates="user_comments")
# post relationship 
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)

with app.app_context():
    db.create_all()
    
#Login_manager

login_manager =  LoginManager()
login_manager.init_app(app)

# user_loader

@login_manager.user_loader
def load_user(id):
    try:
        User.query.get(id)
    except:
        return None
    else:
        return User.query.get(id)

# admin_only decorator


def admin_only(f):
    def decorated_function(*args, **kwargs):
        if current_user is None:
            return redirect(url_for('login', next=request.url))
        elif current_user.id != 1:
            abort(403)
        else:
            return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function


@app.route('/')
def get_all_posts():
    try:
        current_user.id
    except:
        user_id = None
    else:
        user_id = current_user.id
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, user_id = user_id)


@app.route('/register', methods=['POST','GET' ])
def register():
    Form = RegisterForm()
    if Form.validate_on_submit():
        Email = Form.email.data
        if User.query.filter_by(email = Email).first() == None:
            new_user = User(
                email = Form.email.data,
                name = Form.name.data,
                password = generate_password_hash(Form.password.data, "pbkdf2:sha256", 8)
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        else:
            flash("The email you entered is already registered! Try logging in instead.", 'danger')
    return render_template("register.html", form = Form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST','GET' ])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        Email = form.email.data
        if User.query.filter_by(email = Email).first() == None:
            flash( "Given email is not registered. Try again!", 'danger')
            return render_template("login.html", form = form, logged_in=current_user.is_authenticated)
        else:
            User_logged_in = User.query.filter_by(email = Email).first()
            if check_password_hash(User_logged_in.password, form.password.data):
                login_user(User_logged_in)
                return redirect(url_for('get_all_posts'))
            else:
                flash("The password you entered is incorrect. Try again!", 'danger')
                return render_template("login.html", form = form, logged_in=current_user.is_authenticated)
    return render_template("login.html", form = form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST','GET' ])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    all_comments = Comment.query.filter_by(post_id=post_id).all()
    try:
        current_user.id
    except:
        user_id = None
    else:
        user_id = current_user.id
    if comment_form.validate_on_submit():
        if user_id == None:
            flash("You need to register or login to comment.")
            return redirect(url_for('login'))
        else:
            new_comment = Comment(
                text = comment_form.text.data,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id = post_id))
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, user_id = user_id, form = comment_form, comments = all_comments )


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route('/contact', methods=['POST', 'GET'])
def contact():
    if request.method == 'GET':
        return render_template('contact.html', msg_sent=False,  logged_in=current_user.is_authenticated)
    elif request.method == 'POST':
        username = request.form['username']
        message = request.form['message']
        phone = request.form['phone']
        email = request.form['email']
        send_mail(username, message, phone, email)
        return render_template('contact.html', msg_sent=True, logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=['POST','GET' ])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
