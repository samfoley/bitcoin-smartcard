import subprocess
from flask import Flask, flash, url_for, redirect, render_template, request, session
import tx

app = Flask(__name__)

DEFAULT_PRICE = 0.1

checkout_items = []

@app.route('/')
def home():
	url_for('static', filename='bitcoin-logo.jpg')
	balance = tx.balance()
	return render_template('index.html',error=None, balance=balance, transactions=tx.get_transactions())

@app.route('/tx', methods=['POST'])
def transaction():
	balance = tx.balance()
	try:	
		if tx.balance() < float(request.form['amount']):
			return render_template('index.html',error="Not enough funds available", amount=request.form['amount'], address=request.form['address'], balance=balance)
		tx.write_transaction(request.form['address'], float(request.form['amount']))
	except tx.InvalidAddress:
		return render_template('index.html',error="Invalid to address", amount=request.form['amount'], address=request.form['address'], balance=balance)
	except ValueError:
		return render_template('index.html',error="Invalid amount", amount=request.form['amount'], address=request.form['address'], balance=balance)
	subprocess.call(['~/capstone/src/bitcoin_usb.sh'],shell=True)
	return redirect(url_for('status'));

@app.route('/cancel', methods=['POST'])
def cancel():
	subprocess.call(['~/capstone/src/tx_cancel.sh'],shell=True)
	return redirect(url_for('home'));
	
@app.route('/status')
def status():
	fp = open('../src/bitcoin_usb.log', 'r')
	lines = fp.readlines()	
		
	status='waiting'
	if len(lines)>0:
		status = lines[-1]
	if status.find("TX_READY")!=-1:
		if 'raw' in request.args:
			return "TX_READY"
		else:
			return redirect(url_for('confirm'));
	else:
		try:
			if(len(subprocess.check_output(["pidof", "bitcoin"]))==0):
				subprocess.call(['~/capstone/src/bitcoin_usb.sh'],shell=True)
		except subprocess.CalledProcessError:
			subprocess.call(['~/capstone/src/bitcoin_usb.sh'],shell=True)
			
		if 'raw' in request.args:
			return status
		else:
			return render_template('status.html', status=status)

@app.route('/confirm', methods=['GET', 'POST'])
def confirm():
	global checkout_items
	checkout_items = []
		
	if request.method == 'POST':
		if request.form['send'] == 'Send':
			txid = tx.send_transaction('0001.signed')
			flash("Transaction sent")
			return redirect(url_for('home'))
		else:
			return redirect(url_for('home'))
	else:
		transaction = tx.decode_transaction('0001.signed')
		return render_template('confirm.html', address=transaction['address'][0].encode('UTF-8'), amount=transaction['amount'])

@app.route('/checkout', methods=['GET','POST'])
def checkout():
	global checkout_items
	if request.method == 'POST':
		checkout_items = []
		flash("Order cleared")
		return redirect(url_for('home'))
	else:
		amount = 0.0
		
		for item in checkout_items:
			amount += item[1]
			
		return render_template('checkout.html', items=checkout_items, amount=amount)

@app.route('/additem', methods=['GET'])
def additem():
	global checkout_items
	item = (request.args.get('item',''), float(request.args.get('price', DEFAULT_PRICE)))

	checkout_items.append(item)
	
	flash("Item added")
	return redirect(url_for('checkout'))
	
app.secret_key = 'hju96t976t9yf865fd6hgfkh'
	
if __name__ == '__main__':
	app.debug = True
	app.run(host='0.0.0.0')
