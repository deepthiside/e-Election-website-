from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash  # Keep this
from sqlalchemy import func, distinct
from functools import wraps
from config import Config
from models import db, User, Election, Candidate, Vote, UserVoteStatus
from forms import LoginForm, VoteForm, ElectionForm, RegisterForm, VoterForm, CandidateForm
import datetime
import pytz

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('You need administrator privileges to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()
    if form.is_submitted():
        print("Register form submitted")
        print(f"Form data: {form.data}")
        print(f"Form errors: {form.errors}")
    if form.validate_on_submit():
        try:
            user = User(id=form.user_id.data)
            user.set_password(form.password.data)
            user.is_admin = False
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {e}', 'danger')

    return render_template('register.html', title='Register', form=form)

@app.route('/admin/voters', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_voters():
    voter_form = VoterForm()
    if voter_form.validate_on_submit():
        try:
            new_voter = User(id=voter_form.user_id.data, is_admin=voter_form.is_admin.data)
            new_voter.set_password(voter_form.password.data)
            db.session.add(new_voter)
            db.session.commit()
            flash(f'Voter {new_voter.id} added successfully.', 'success')
            return redirect(url_for('manage_voters'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding voter: {e}', 'danger')

    voters = User.query.order_by(User.id).all()

    user_vote_counts = dict(db.session.query(
        UserVoteStatus.user_id,
        func.count(UserVoteStatus.id)
    ).group_by(UserVoteStatus.user_id).all())

    return render_template('admin/manage_voters.html',
                           title='Manage Voters',
                           voters=voters,
                           voter_form=voter_form,
                           user_vote_counts=user_vote_counts)

@app.route('/admin/election_list')
@login_required
@admin_required
def admin_election_list():
     elections = Election.query.order_by(Election.start_time.desc()).all()
     just_created = request.args.get('created', False)

     return render_template('admin/election_list.html',
                            title='All Elections',
                            elections=elections,
                            just_created=just_created)

@app.route('/admin/delete_election/<int:election_id>', methods=['POST'])
@login_required
@admin_required
def delete_election(election_id):
    election = Election.query.get_or_404(election_id)

    try:
        Vote.query.filter_by(election_id=election_id).delete()
        UserVoteStatus.query.filter_by(election_id=election_id).delete()
        Candidate.query.filter_by(election_id=election_id).delete()
        db.session.delete(election)
        db.session.commit()
        flash(f'Election "{election.name}" has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting election: {e}', 'danger')

    return redirect(url_for('admin_election_list'))

@app.context_processor
def inject_now():
    kolkata_tz = pytz.timezone('Asia/Kolkata')
    now_time = datetime.datetime.now(kolkata_tz)
    return {'now': now_time}

@app.route('/')
def index():
    ist_tz = pytz.timezone('Asia/Kolkata')
    now = datetime.datetime.now(ist_tz)

    if current_user.is_authenticated:
        voted_election_ids = db.session.query(UserVoteStatus.election_id).filter_by(user_id=current_user.id).all()
        voted_election_ids = [id for (id,) in voted_election_ids]
        available_elections = []
        active_elections = []
        for election in Election.query.filter(Election.is_active == True).all():
            start_time = election.start_time
            end_time = election.end_time
            if start_time and not start_time.tzinfo:
                start_time = start_time.replace(tzinfo=ist_tz)
            if end_time and not end_time.tzinfo:
                end_time = end_time.replace(tzinfo=ist_tz)
            if (start_time and end_time and start_time <= now and end_time >= now):
                active_elections.append(election)
                if not voted_election_ids or election.id not in voted_election_ids:
                    available_elections.append(election)

        voted_elections = Election.query.filter(
            Election.id.in_(voted_election_ids)
        ).all() if voted_election_ids else []
    else:
        available_elections = []
        voted_elections = []
        active_elections = []

    upcoming_elections = []
    for election in Election.query.filter(Election.is_active == True).order_by(Election.start_time).all():
        start_time = election.start_time
        if start_time and not start_time.tzinfo:
            start_time = start_time.replace(tzinfo=ist_tz)
        if start_time and start_time > now:
            if election not in active_elections:
                upcoming_elections.append(election)

    finished_elections = []
    for election in Election.query.order_by(Election.end_time.desc()).limit(10).all():
        end_time = election.end_time
        if end_time and not end_time.tzinfo:
            end_time = end_time.replace(tzinfo=ist_tz)
        if end_time and end_time < now:
            finished_elections.append(election)
            if len(finished_elections) >= 5:
                break

    return render_template('index.html',
                          title='Election Dashboard',
                          available_elections=available_elections,
                          voted_elections=voted_elections,
                          upcoming_elections=upcoming_elections,
                          finished_elections=finished_elections,
                          now=now,
                          datetime=datetime)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.get(form.user_id.data)
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('index')
        return redirect(next_page)

    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/vote/<int:election_id>', methods=['GET', 'POST'])
@login_required
def vote(election_id):
    election = Election.query.get_or_404(election_id)
    ist_tz = pytz.timezone('Asia/Kolkata')
    now = datetime.datetime.now(ist_tz)

    if not election.is_active:
        flash('This election is not currently active.', 'warning')
        return redirect(url_for('index'))

    if UserVoteStatus.query.filter_by(user_id=current_user.id, election_id=election_id).first():
        flash('You have already voted in this election.', 'info')
        return redirect(url_for('results', election_id=election_id))

    candidates = Candidate.query.filter_by(election_id=election_id).all()
    if not candidates:
        flash('No candidates available for this election.', 'warning')
        return redirect(url_for('index'))

    form = VoteForm()
    form.candidate_id.choices = [(c.id, c.name) for c in candidates]

    if form.validate_on_submit():
        try:
            vote = Vote(election_id=election_id, candidate_id=form.candidate_id.data)
            db.session.add(vote)
            user_vote_status = UserVoteStatus(user_id=current_user.id, election_id=election_id)
            db.session.add(user_vote_status)
            db.session.commit()
            flash('Your vote has been recorded. Thank you for voting!', 'success')
            return redirect(url_for('results', election_id=election_id))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while recording your vote: {e}', 'danger')

    return render_template('vote.html',
                          title=f'Vote: {election.name}',
                          election=election,
                          form=form,
                          candidates=candidates)

@app.route('/results/<int:election_id>')
def results(election_id):
    election = Election.query.get_or_404(election_id)
    ist_tz = pytz.timezone('Asia/Kolkata')
    now = datetime.datetime.now(ist_tz)

    end_time = election.end_time
    if end_time and not end_time.tzinfo:
        end_time = end_time.replace(tzinfo=ist_tz)

    if end_time and end_time > now and election.is_active and not (current_user.is_authenticated and current_user.is_admin):
        flash('Results are not available until the election has ended.', 'info')
        return redirect(url_for('index'))

    candidates = Candidate.query.filter_by(election_id=election_id).all()
    results = {}
    total_votes = 0

    for candidate in candidates:
        vote_count = Vote.query.filter_by(election_id=election_id, candidate_id=candidate.id).count()
        results[candidate.id] = {
            'name': candidate.name,
            'votes': vote_count
        }
        total_votes += vote_count

    for candidate_id in results:
        if total_votes > 0:
            results[candidate_id]['percentage'] = (results[candidate_id]['votes'] / total_votes) * 100
        else:
            results[candidate_id]['percentage'] = 0

    return render_template('results.html',
                          title=f'Results: {election.name}',
                          election=election,
                          results=results,
                          total_votes=total_votes)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    user_count = User.query.count()
    election_count = Election.query.count()
    vote_count = Vote.query.count()

    ist_tz = pytz.timezone('Asia/Kolkata')
    now = datetime.datetime.now(ist_tz)
    active_elections = Election.query.filter(
        Election.is_active == True,
        Election.start_time <= now,
        Election.end_time >= now
    ).all()

    return render_template('admin/dashboard.html',
                          title='Admin Dashboard',
                          user_count=user_count,
                          election_count=election_count,
                          vote_count=vote_count,
                          active_elections=active_elections)

@app.route('/admin/elections', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_elections():
    form = ElectionForm()
    if form.is_submitted():
        print("Form submitted")
        print(f"Form data: {form.data}")
        print(f"Form errors: {form.errors}")
    if form.validate_on_submit():
        try:
            print("Form validated successfully")
            election = Election(
                name=form.name.data,
                position=form.position.data,
                start_time=form.start_time.data,
                end_time=form.end_time.data,
                is_active=form.is_active.data
            )
            print(f"Created election object: {election.name}, {election.position}")
            db.session.add(election)
            print("Added to session")
            db.session.commit()
            print("Committed to database")
            flash(f'Election "{election.name}" created successfully.', 'success')
            print(f"Redirecting to {url_for('admin_election_list', created=True)}")
            return redirect(url_for('admin_election_list', created=True))
        except Exception as e:
            db.session.rollback()
            print(f"Error: {e}")
            flash(f'Error creating election: {e}', 'danger')

    return render_template('admin/manage_elections.html',
                          title='Manage Elections',
                          form=form)

@app.route('/admin/elections/<int:election_id>/candidates', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_candidates(election_id):
    election = Election.query.get_or_404(election_id)
    candidates = Candidate.query.filter_by(election_id=election_id).all()
    form = CandidateForm()

    if form.validate_on_submit():
        try:
            candidate = Candidate(
                name=form.name.data,
                election_id=election_id
            )
            db.session.add(candidate)
            db.session.commit()
            flash(f'Candidate "{form.name.data}" added successfully.', 'success')
            return redirect(url_for('manage_candidates', election_id=election_id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding candidate: {e}', 'danger')

    return render_template('admin/manage_candidates.html',
                          title=f'Manage Candidates - {election.name}',
                          election=election,
                          candidates=candidates,
                          form=form)

@app.route('/init-db')
def init_db():
    db.create_all()
    admin = User.query.filter_by(id='admin').first()
    if not admin:
        admin = User(id='admin', is_admin=True)
        admin.set_password('admin123')  # Keep this
        db.session.add(admin)
        db.session.commit()
        flash('Database initialized with admin user.', 'success')
    else:
        flash('Database already initialized.', 'info')

    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
