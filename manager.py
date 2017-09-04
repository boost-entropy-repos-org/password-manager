import argparse
import bcrypt
import passgen
import pickle
import os
import sys

from simplecrypt import encrypt, decrypt
from os import path


MASTER_PASSWORD_ENV = 'MASTER_PASSWORD'


class CredentialManager:

	CREDENTIALS_FILE = 'password.vault'

	def __init__(self, directory, master_password):
		"""
		Initializes a new password manager which will store
		passwords in an encrypted file in `directory`.

		Raises:
			ValueError: if directory does not exist
		"""
		self.credentials = {}
		self.credentials_file = path.join(directory, self.CREDENTIALS_FILE)
		self.master_password = master_password

		if not path.isdir(directory):
			raise ValueError('Directory does not exist: {}'.format(directory))

		if path.exists(self.credentials_file):
			self._load_credentials_from_disk()

	def _load_credentials_from_disk(self):
		with open(self.credentials_file, 'rb') as f:
			self.credentials = Credential.decrypt(f.read(), self.master_password)

	def _save_credentials_to_disk(self):
		""""""
		with open(self.credentials_file, 'wb') as f:
			encrypted_data = Credential.encrypt(self.credentials, self.master_password)
			f.write(encrypted_data)

	def get(self, site, user):
		if (site,user) not in self.credentials:
			self.set(site, user)
		return self.credentials[(site, user)]

	def set(self, site, user, password=None):
		self.credentials[(site, user)] = Credential(site, user, password)
		self._save_credentials_to_disk()


class Credential:
	""""""
	def __init__(self, site, user, password=None):
		self.site = site
		self.user = user
		self.password = password if password else Credential._generate_password()

	def _generate_password():
		"""Generates a random password."""
		return passgen.passgen(punctuation=True)

	def encrypt(credentials, master_password):
		print("Encrypting credentials...", end="")
		sys.stdout.flush()
		encrypted_data = encrypt(master_password, pickle.dumps(credentials))
		print("done")
		return encrypted_data
	
	def decrypt(encrypted_data, master_password):
		print("Decrypting credentials...", end="")
		sys.stdout.flush()
		credentials = pickle.loads(decrypt(master_password, encrypted_data))
		print("done")
		return credentials

	def __str__(self):
		return "Password for user '{}' on site '{}' is '{}'.".format(self.user, self.site, self.password)


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Credential Manager')
	parser.add_argument('site', help='Website associated with credential.')
	parser.add_argument('user', help='Username associated with credential.')
	parser.add_argument('password', help='Password associated with credential. '
		'If not supplied, one is generated.', nargs='?')
	parser.add_argument('--directory', help='Directory where credentials are stored.', default='.')

	args = parser.parse_args()

	master_password = os.environ[MASTER_PASSWORD_ENV]

	# Initialize a new CredentialManager in the specified directory
	# using our master password for encryption and decryption.
	cm = CredentialManager(args.directory, master_password)

	if args.password:
		# Store this credential
		cm.set(args.site, args.user, args.password)

	# Get the password for this (site, user) combination,
	# auto-generating a password, if necessary
	print(cm.get(args.site, args.user))
