from database.loader import session_maker
from database.models.rating_users import RatingUsers
from database.models.areas import Areas
from database.models.reviews import Reviews
from database.models.links import Links

from flask import Flask, render_template, url_for, request, redirect, flash, jsonify, make_response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from flask_restful import Resource, Api, reqparse


app = Flask(__name__)
app.debug = True
manager = LoginManager(app)
manager.login_view = 'enter'
app.config['SECRET_KEY'] = 'cf39dca40b607927dc14bc446005ce39b6079ea2'

api = Api(app)
jwt = JWTManager(app)


@manager.user_loader
def load_user(rating_users_id):
    with session_maker() as db_session:
        return db_session.query(RatingUsers).get(rating_users_id)


# Вход/регистрация/выход

@app.route('/enter', methods=['POST', 'GET'])
def enter():
    if current_user.is_authenticated:
        return redirect(url_for('admin'))
    if request.method == "POST":
        print('входим')
        login = request.form.get('login').lstrip(' ')
        password = request.form.get('password')
        if login and password:
            with session_maker() as db_session:
                user = db_session.query(RatingUsers).filter_by(login=login).first()
                if user and check_password_hash(user.password_hash, password):
                    login_user(user)                   
                    return redirect(url_for('admin'))
                else:
                    flash(
                        'Логин и/или пароль некорректный',
                        category='badge bg-danger-subtle border border-danger-subtle text-danger-emphasis rounded-pill'
                    )
        else:
            flash('Заполните оба поля',
                  category='badge bg-danger-subtle border border-danger-subtle text-danger-emphasis rounded-pill')
    return render_template('enter.html')


@app.route('/reg', methods=['POST', 'GET'])
def reg():
    if request.method == "POST":
        name = request.form.get('name')
        login = request.form.get('login')
        password = request.form.get('password')
        password2 = request.form.get('password2')

        with session_maker() as db_session:
            if len(login) == 0 or len(name) == 0 or len(password) == 0 or len(password2) == 0:
                flash('Заполните все поля', category='error')
            elif len(db_session.query(RatingUsers).filter_by(login=login).all()) > 0:
                flash('Уже есть такой логин', category='error')
            elif password != password2:
                flash('Пароли не совпадают', category='error')

            else:
                hash_pwd = generate_password_hash(password)
                new_user = RatingUsers(login=login.lstrip(' '), name=name.lstrip(' '), password_hash=hash_pwd)  # noqa
                new_user.token = new_user.get_token()
                db_session.add(new_user)
                db_session.commit()
                flash('Вы зарегистрированы!', category='success')

                return redirect(url_for('enter'))

    return render_template('registration.html')


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('enter'))


# Личный кабинет

@app.route('/admin', methods=['POST', 'GET'])
@login_required
def admin():
    with session_maker() as db_session:
        user = db_session.query(RatingUsers).get(current_user.id)
        token = user.token
        places = db_session.query(Areas).filter_by(id_rating_user=current_user.id).all()
        return render_template('admin.html', places=places, token=token)


@app.route('/add_area', methods=['POST', 'GET'])
@login_required
def add_area():
    if request.method == "POST":
        area = request.form.get('area')

        with session_maker() as db_session:
            if len(area) == 0:
                flash('Название места нем может быть пустым', category='error')
            elif len(db_session.query(Areas).filter_by(id_rating_user=current_user.id).filter_by(area=area).all()) > 0:
                flash('У вас уже есть такое место!', category='error')
            else:
                new_area = Areas(area=area, id_rating_user=current_user.id)
                db_session.add(new_area)
                db_session.commit()
                
                place1 = Links(name=request.form.get('place_1'), link=request.form.get('place_1_link'), checkbox=request.form.get('checkbox1'), id_area=new_area.id_area)
                place2 = Links(name=request.form.get('place_2'), link=request.form.get('place_2_link'), checkbox=request.form.get('checkbox2'), id_area=new_area.id_area)
                place3 = Links(name=request.form.get('place_3'), link=request.form.get('place_3_link'), checkbox=request.form.get('checkbox3'), id_area=new_area.id_area)

                db_session.add_all([place1, place2, place3])
                db_session.commit()
                flash('Вы добавили новое место', category='success')
                return redirect(url_for('admin'))
    return render_template('add_area.html')


@app.route('/baza/<string:id_area>/update', methods=['POST', 'GET'])
@login_required
def baza_update(id_area):
    with session_maker() as db_session:
        update_area = db_session.query(Areas).get(id_area) # это запись в таблице
        from_links = db_session.query(Links).filter_by(id_area=id_area).all()
        area = request.form.get('area')
        
        if request.method == "POST":
            if len(request.form.get('area')) == 0:
                flash('Название места нем может стать пустым', category='error')
            elif len(db_session.query(Areas).filter_by(id_rating_user=current_user.id).filter_by(area=area).all()) > 0 and db_session.query(Areas).filter_by(id_rating_user=current_user.id).filter_by(area=area).first().id_area != int(id_area):
                flash('Уже вас уже есть такое место!', category='error')
            else:
                update_area.area = request.form.get('area')
                db_session.commit()

                i = db_session.query(Links).get(from_links[0].id)
                i.name = request.form.get('place_1')
                i.link = request.form.get('place_1_link')
                i.checkbox = request.form.get('checkbox1')
                db_session.commit()

                i = db_session.query(Links).get(from_links[1].id)
                i.name = request.form.get('place_2')
                i.link = request.form.get('place_2_link')
                i.checkbox = request.form.get('checkbox2')
                db_session.commit()

                i = db_session.query(Links).get(from_links[2].id)
                i.name = request.form.get('place_3')
                i.link = request.form.get('place_3_link')
                i.checkbox = request.form.get('checkbox3')
                db_session.commit()

                flash('Вы обновили данные', category='success')
                return redirect(url_for('admin'))         
        return render_template('update_area.html', upadate_area=update_area, place_1=from_links[0], place_2=from_links[1], place_3=from_links[2])
    

@app.route('/baza/<string:id_area>')
@login_required
def baza_rev(id_area):
    with session_maker() as db_session:
        rev = db_session.query(Reviews).filter_by(id_area=id_area).order_by(Reviews.date.desc()).all()
        area = db_session.query(Areas).filter_by(id_area=id_area).first().area
        return render_template('baza.html', rev=rev, area=area)


@app.route('/baza/<string:id_area>/del')
@login_required
def baza_del(id_area):
    with session_maker() as db_session:
        del_area = db_session.query(Areas).get(id_area)
        try:
            db_session.delete(del_area)
            db_session.commit()
            flash('Запись удалена', category='success')
            return redirect('/admin')
        except (Exception,):
            flash('Ошибочка удаления', category='error')
            return redirect('/admin')
        
@app.route('/update_token')
@login_required
def update_token():
    with session_maker() as db_session:  
        try:
            user = db_session.query(RatingUsers).get(current_user.id)
            user.token = user.get_token()
            db_session.commit()
            return redirect('/admin')
        
        except (Exception,):
            flash('Ошибка обновления токена', category='error')
            return redirect('/admin')        


@app.route('/api/all_reviews/<string:area>')
def all_reviews(area):
    api_token = request.headers.get('X-API-Token')

    with session_maker() as db_session:
        areas = db_session.query(Areas).filter_by(area=area).all()

        for i in areas:
            user = db_session.query(RatingUsers).filter_by(id=i.id_rating_user).first()
            if api_token == user.token:
                result = db_session.query(Reviews).filter_by(id_area=i.id_area).order_by(Reviews.date.desc()).all()
                reviews = []

                for review in result:
                    reviews.append({
                    'id': review.id,
                    'id_1C': review.id_1C,
                    'mail': review.mail,
                    'review': review.review,
                    'date': str(review.date),
                    })

                reviews_json = jsonify(reviews)
                response = make_response(reviews_json)  
                response.headers['Content-Type'] = 'application/json'        
                # no_code = response.get_data(as_text=True)
                # data = json.loads(no_code)
                # print(data)
                
                return response     
    return {'error': 'Invalid API token'}, 401


@app.route('/api/last_review/<string:id_1C>')
def last_review(id_1C):
    api_token = request.headers.get('X-API-Token')
    with session_maker() as db_session:
        last_review = db_session.query(Reviews).filter_by(id_1C=id_1C).order_by(Reviews.date.desc()).first()
        user = db_session.query(RatingUsers).filter_by(id=last_review.user_id).first()
        if api_token == user.token:
            review_data = {
            'id': last_review.id,
            'id_1C': last_review.id_1C,
            'mail': last_review.mail,
            'review': last_review.review,
            'date': str(last_review.date),
            }

            review_json = jsonify(review_data)
            response = make_response(review_json)  
            response.headers['Content-Type'] = 'application/json'        
            # no_code = response.get_data(as_text=True)
            # data = json.loads(no_code)
            # print(data)
            return response
    return {'error': 'Invalid API token'}, 401


# Клиентская часть

@app.route('/stars/<string:area>/<string:id_area>/<int:user_id>/<string:id_1C>', methods=['POST', 'GET'])
def index(area, id_area, user_id, id_1C):  
    with session_maker() as db_session:
        if request.method == "POST":
            est = request.form['simple-rating']
            if est in ['5', '4']:
                mail = str('0')
                review = str(request.form['simple-rating'])
                good_review = Reviews(mail=mail, review=review, id_area=id_area , id_1C=id_1C, user_id=user_id)
                try:
                    db_session.add(good_review)
                    db_session.commit()
                except (Exception,):
                    pass
                from_links = db_session.query(Links).filter_by(id_area=id_area).all()
                return render_template('links.html', links=from_links)
            
            else:
                return render_template('page2.html', est=est, id_area=id_area, user_id=user_id, id_1C=id_1C)
        else:
            return render_template('rating.html')


@app.route('/reviews/<string:est>/<string:id_area>/<int:user_id>/<string:id_1C>', methods=['POST', 'GET'])
def add_rev(est, id_area, user_id, id_1C ):
    with session_maker() as db_session:
        if request.method == "POST":
            mail = request.form['mail']
            review = 'Оценка: ' + est + ' --> ' + request.form['reviews']

            if len(mail) < 6 or len(review) < 16:
                flash('Мало символов. Пожалуйста напишите телефон/email и ваш отзыв.', category='error')
            else:
                bad_review = Reviews(mail=mail, review=review, id_area=id_area, id_1C=id_1C, user_id=user_id)
                try:
                    db_session.add(bad_review)
                    db_session.commit()
                    flash('Сообщение отправлено', category='success')
                except (Exception,):
                    flash('Ошибка добавления в базу', category='error')
    return render_template('page2.html', est=est, id_area=id_area, user_id=user_id)
                


if __name__ == '__main__':
    app.run(debug=True)


