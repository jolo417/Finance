import os
import re

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash


from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = :user_id GROUP BY symbol;", user_id=session['user_id'])
    all_total = 0
    if symbols != []:
        stocks = []
        current_cash = db.execute("SELECT cash FROM users WHERE id = :user_id;", user_id=session['user_id'])
        for symbol in symbols:
            info = lookup(symbol['symbol'])
            shares = db.execute("SELECT SUM(shares) FROM transactions WHERE user_id=:user_id AND symbol = :symbol;", user_id=session['user_id'], symbol=info['symbol'])
            if shares[0]['SUM(shares)'] == 0:
                continue
            else:
                data = {}
                data['name'] = info['name']
                data['symbol'] = info['symbol']
                data['price'] = info['price']
                data['shares'] = shares[0]['SUM(shares)']
                data['total'] = data['shares'] * data['price']
                stocks.append(data)
        for i in range(len(stocks)):
            all_total += stocks[i]['total']
        all_total += current_cash[0]['cash']
        for i in range(len(stocks)):
            stocks[i]['price'] = usd(stocks[i]['price'])
            stocks[i]['total'] = usd(stocks[i]['total'])
        return render_template("index.html", stocks=stocks, current_cash=usd(current_cash[0]['cash']), all_total=usd(all_total))
    else:
        current_cash = db.execute("SELECT cash FROM users WHERE id=:user_id;", user_id=session['user_id'])
        return render_template("index.html", current_cash=usd(current_cash[0]['cash']), all_total = usd(current_cash[0]['cash']))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        try:
            symbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            return apology("You need to enter an input", 403)
        if not symbol:
            return apology("You need to enter a valid symbol", 403)
        if not shares or shares <= 0:
            return apology("You need to enter a share", 403)
        cash_now = db.execute("SELECT cash FROM users WHERE id=:user_id;", user_id=session["user_id"])
        cash_now = int(cash_now[0]['cash'])
        if (shares * symbol['price']) > cash_now:
            return apology("You can not afford this", 403)
        else:
            db.execute("INSERT INTO transactions (symbol, shares, price, user_id) VALUES (:symbol, :shares, :price, :user_id);", symbol=symbol['symbol'], shares=shares, price=symbol['price'], user_id=session["user_id"])
            db.execute("UPDATE users SET cash=cash-:total_price WHERE id=:user_id;", total_price=shares*symbol['price'], user_id=session["user_id"])
            return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    stocks = db.execute("SELECT symbol, shares, price, date_time FROM transactions WHERE user_id=:user_id", user_id=session['user_id'])
    for stock in stocks:
        stock['price'] = usd(stock['price'])
    return render_template("history.html", stocks=stocks)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        if not request.form.get("symbol"):
            return apology("No symbol",  403)
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Not a valid symbol", 403)
        return render_template("quoted.html", stock=stock)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        if not username:
            return apology("You must provide a username", 403)
        password = request.form.get("password")
        if len(password) < 8:
            return apology("Password must be 8 characters")
        if re.search('[0-9]',password) is None:
            return apology("Make sure your password has a number in it")
        if re.search('[A-Z]',password) is None:
            return apology("Make sure your password has a capital letter in it")
        if re.search('[a-z]', password) is None:
            return apology("Make sure your password has a lower case letter in it")
        if not password:
            return apology("You must provide a password.", 403)
        confirmation = request.form.get("confirmation")
        if not confirmation:
            return apology("Please provide the password again", 403)
        if password != confirmation:
            return apology("passwords do not match", 403)
        row = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        if len(row) >= 1:
            return apology("This username is already taken", 403)
        s = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :s)", username=request.form.get("username"), s=s)
        new_user = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        session["user_id"] = new_user[0]["id"]
        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        try:
            symbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            return apology("You need to enter an input", 403)
        if not symbol:
            return apology("You need to enter a valid symbol", 403)
        if not shares or shares <= 0:
            return apology("You need to enter a share", 403)
        current_stock = db.execute("SELECT SUM(shares) FROM transactions WHERE user_id=:user_id AND symbol=:symbol;", user_id=session['user_id'], symbol=symbol['symbol'])
        if not current_stock[0]['SUM(shares)'] :
            return apology("You do not own this stock", 403)
        if shares > current_stock[0]['SUM(shares)']:
            return apology("You do not own that many stocks", 403)
        db.execute("INSERT INTO transactions (symbol, shares, price, user_id) VALUES (:symbol, :shares, :price, :user_id);", symbol=symbol['symbol'], shares=-shares, price=symbol['price'], user_id=session["user_id"])
        db.execute("UPDATE users SET cash = cash + :total_price WHERE id = :user_id;", total_price=shares*symbol['price'], user_id=session["user_id"])
        return redirect("/")
    else:
        return render_template("sell.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
