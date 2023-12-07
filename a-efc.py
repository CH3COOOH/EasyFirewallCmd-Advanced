#！/usr/bin/env python3

import sys
import os

class CParser:
	def __init__(self, isPermanent=True):
		self.env = {}
		self.config = []
		self.CMD_TEMPALTE = 'firewall-cmd '
		if isPermanent == True:
			self.CMD_TEMPALTE += '--permanent '
	
	def _isIP(self, text):
		if ('.' in text) == False:
			return False
		if len(text.split('.')) == 4:
			return True
		else:
			return False
	
	def _isVar(self, text):
		return text[0] == '$'
	
	def _getRawOrVar(self, text):
		if self._isVar(text) == True:
			return self.env[text]
		return text
	
	def _parse_host(self, text, direction):
		args = {'lo': ['-s', '--sport', '-o'], 'de': ['-d', '--dport']}
		cbuf = ''
		if text == '*':
			return ''
		host, port = text.split(':')
		if host == '*':
			## *:?
			return f"{args[direction][1]} {self._getRawOrVar(port)} "
		
		if self._isIP(self._getRawOrVar(host)) == True:
			## 192.168.1.1:?
			cbuf += f"{args[direction][0]} {self._getRawOrVar(host)} "
		else:
			cbuf += f"{args[direction][2]} {self._getRawOrVar(host)} "
		if port != '*':
				## 192.168.1.1:8080
				cbuf +=  f"{args[direction][1]} {self._getRawOrVar(port)} "
		return cbuf

	def _gen_cmd(self, param_line):
		## param_line
		## [OP[0] PRI[1] PROTOCOL[2] LOCAL[3] REMOTE[4] ACT[5]]
		## firewall-cmd --add-rule ipv4 filter OUTPUT 0 -p tcp -o eth0 --dport 22 -j DROP
		cmd  = self.CMD_TEMPALTE
		cmd += '--direct --%s-rule ipv4 filter OUTPUT %s -p %s ' % (
			{'+': 'add', '-': 'remove'}[param_line[0]],
			param_line[1],
			param_line[2])
		cmd += self._parse_host(param_line[3], 'lo')
		cmd += self._parse_host(param_line[4], 'de')
		cmd += '-j ' + param_line[5]
		return cmd
	
	def read(self, fpath):
		with open(fpath, 'r') as o:
			raw_lines = o.readlines()
		for buf in raw_lines:
			if (buf in ['\n', '\r\n']) or ('#' in buf):
				continue
			buf = buf.strip()
			param = buf.split()
			if param[0][0] == '$':
				## variable: $NAME VALUE
				self.env[param[0]] = param[1]
			else:
				## [OP PRI LOCAL REMOTE ACT]
				self.config.append(param)
		return 0
	
	def get_cmd_all(self):
		for c in self.config:
			yield self._gen_cmd(c)


def main(config_file, isExcute, isPermanent):
	parser = CParser(isPermanent)
	parser.read(config_file)
	for cmd in parser.get_cmd_all():
		print(cmd)
		if isExcute == True:
			os.system(cmd)
	if isExcute == True:
		os.system('firewall-cmd --reload')

if __name__ == '__main__':
	usage = 'Usage: a-efc config.txt [-e] [-p]'
	isExcute = False
	isPermanent = False
	try:
		if '-e' in sys.argv:
			isExcute = True
		if '-p' in sys.argv:
			isPermanent = True
		config_file = sys.argv[1]
	except:
		print(usage)
		exit(-1)
	
	main(config_file, isExcute, isPermanent)