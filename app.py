import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, is_negative

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    portfolio = db.execute("SELECT * FROM portfolio")

    result = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    cash = result[0]['cash']

    grand_total = cash

    for stock in portfolio:
        price = lookup(stock['stock'])['price']
        total = stock['quantity'] * price
        stock.update({'price': price, 'total': total})
        grand_total += total

    return render_template("index.html", stocks=portfolio, cash=cash, total=(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    elif request.method == "POST":

        if lookup(request.form.get("symbol")) == None:
            return apology("invalid stock symbol")
        shares = request.form.get("shares")

        if not shares.isdigit():
            return apology("You cannot purchase partial shares.")

        stock_info = lookup(request.form.get("symbol"))
        cost = int(request.form.get("shares")) * stock_info['price']

        cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])

        if int(cash[0]['cash']) > int(cost):
            db.execute("UPDATE users SET cash = cash - :total_cost WHERE id = :user_id",
                       total_cost=cost, user_id=session["user_id"])
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price, type) VALUES (:user_id, :symbol, :shares, :price, :type)",
                       user_id=session["user_id"], symbol=stock_info['symbol'], shares=request.form.get("shares"), price=cost, type="bought")
        else:
            return apology("Cannot afford the number of shares at the current price.")

        curr_portfolio = db.execute("SELECT quantity FROM portfolio WHERE stock=:stock", stock=stock_info["symbol"])
        if not curr_portfolio:
            db.execute("INSERT INTO portfolio (stock, quantity) VALUES (:stock, :quantity)",
                       stock=stock_info["symbol"], quantity=int(request.form.get("shares")))

        else:
            db.execute("UPDATE portfolio SET quantity=quantity+:quantity WHERE stock=:stock",
                       quantity=int(request.form.get("shares")), stock=stock_info["symbol"])

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE user_id=:user_id", user_id=session["user_id"])
    return render_template("history.html", stocks=transactions)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        db.execute("DELETE from portfolio")

        portfolio = db.execute(
            "SELECT symbol, SUM(shares) AS quantity FROM transactions WHERE user_id=:user_id GROUP BY symbol ORDER BY symbol", user_id=session["user_id"])

        if portfolio:
            for stock in portfolio:
                symbol = stock['symbol']
                quantity = stock['quantity']

                db.execute("INSERT INTO portfolio (stock, quantity) VALUES (:stock, :quantity)", stock=symbol, quantity=quantity)

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
        result = lookup(request.form.get("symbol"))

        if result == None:
            return apology("invalid stock symbol")

        return render_template("quoted.html", results=result)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username")

        elif not request.form.get("password"):
            return apology("must provide password")

        elif not request.form.get("confirmation"):
            return apology("must confirm password")

        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("passwords doesnt match")

        user_exists = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        if user_exists:
            return apology("Username already taken")

        unhashed_password = request.form.get("password")
        username = request.form.get("username")
        hashed_password = generate_password_hash(unhashed_password)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        symbols = db.execute("SELECT stock FROM portfolio")
        return render_template('sell.html', symbols=symbols)

    else:
        if not request.form.get("symbol"):
            return apology("Must select a stock")

        if not request.form.get("shares") or is_negative(int(request.form.get("shares"))):
            return apology("Must enter a number of shares")

        shares = db.execute("SELECT quantity FROM portfolio WHERE stock = ?", request.form.get("symbol"))
        if shares[0]['quantity'] < int(request.form.get("shares")):
            return apology("You dont have this amount of shares")

        stock_info = lookup(request.form.get("symbol"))
        cost = int(request.form.get("shares")) * stock_info['price']

        db.execute("UPDATE users SET cash = cash + :total_cost WHERE id = :user_id", total_cost=cost, user_id=session["user_id"])
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, type) VALUES (:user_id, :symbol, :shares, :price, :type)",
                   user_id=session["user_id"], symbol=stock_info['symbol'], shares=request.form.get("shares"), price=cost, type="Sold")

        db.execute("UPDATE portfolio SET quantity=quantity-:quantity WHERE stock=:stock",
                   quantity=int(request.form.get("shares")), stock=stock_info['symbol'])

        return redirect("/")


@app.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        password = db.execute("SELECT hash FROM users WHERE id=:user_id", user_id=session["user_id"])[0]["hash"]
        if not check_password_hash(password, request.form.get("old_password")):
            return apology("Wrong password")
        else:
            if request.form.get("new_password") == request.form.get("confirmation"):
                hashed_new_password = generate_password_hash(request.form.get("new_password"))
                db.execute("UPDATE users SET hash=:password WHERE id = :user_id",
                           password=hashed_new_password, user_id=session["user_id"])
            return redirect("/")
    else:
        return render_template("password.html")
