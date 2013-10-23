import subprocess
import json
from electrum import DecodeBase58Check, hash_encode


class InvalidAddress(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

def write_transaction(to_address, to_amount):	
	change_address = "mnCbEM4pZY3E8DbG22faHRupmC39pGZZgC"
	transaction_fee = 0.0001

	unspent_json =  subprocess.check_output(["bitcoind", "-testnet", "listunspent", "0"]) # min 0 confirmations
	unspent = json.loads(unspent_json)

	balance = 0
	for tx in unspent:
		balance += tx['amount']

	change_amount = balance - to_amount - transaction_fee

	transaction = {"version": 1, "locktime": 0, "vin": [], "vout": []}

	for tx in unspent:
		input = {'txid': tx['txid'], 'vout': tx['vout'], 'scriptPubKey': tx['scriptPubKey']}
		transaction['vin'].append(input)

	to = DecodeBase58Check(to_address)
	if to == None:
		raise InvalidAddress("to address decode fail")
	else:
		to = to[::-1]
		
	output_to = {'value': "%.4f" % to_amount, 'address': hash_encode(to[0:20])}
	change = DecodeBase58Check(change_address)[::-1]	
	output_change = {'value': "%.4f" % change_amount, 'address': hash_encode(change[0:20])}

	transaction['vout'] = [output_to, output_change]

	f = open('0001.tx', 'w')
	f.write(json.JSONEncoder().encode(transaction))
	f.close()	

def balance():
	unspent_json =  subprocess.check_output(["bitcoind", "-testnet", "listunspent", "0"]) # min 0 confirmations
	unspent = json.loads(unspent_json)

	balance = 0
	for tx in unspent:
		balance += tx['amount']
	return balance

def get_transactions():
	transactions = json.loads(subprocess.check_output(["bitcoind", "-testnet", "listtransactions"]))
	transactions.reverse()
	
	for tx in transactions:			
		amount = abs(tx['amount'])
		confirmations = 100*min(tx['confirmations'], 6)/6
		if tx['category'] == 'receive' or tx['address'] != "mnCbEM4pZY3E8DbG22faHRupmC39pGZZgC":
			yield {
				'confirmations': confirmations, 
				'amount': amount, 
				'address': tx['address'].encode('UTF-8'), 
				'category': tx['category'].encode('UTF-8')}
	
def decode_transaction(filename):
	f = open(filename, 'r');
	hex_tx = f.read()
	json_tx = subprocess.check_output(["bitcoind", "-testnet", "decoderawtransaction", hex_tx.strip()])
	tx = json.loads(json_tx)
	return {'amount': tx['vout'][0]['value'], 'address': tx['vout'][0]['scriptPubKey']['addresses']}

def send_transaction(filename):
	f = open(filename, 'r');
	hex_tx = f.read()
	return subprocess.check_output(["bitcoind", "-testnet", "sendrawtransaction", hex_tx.strip()])

if __name__ == '__main__':
	write_transaction('mwwdpwLoVr7BsCRyPqwyCCPGS93JenAZRS', 1.0)