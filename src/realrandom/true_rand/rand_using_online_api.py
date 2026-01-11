import aiohttp
import asyncio

async def fetch_random_org_integers(num: int = 1, min_val: int = 1, max_val: int = 100):
	"""Fetches true random integers from random.org using their plain text API."""
	url = "https://www.random.org/integers/"
	params = {
		"num": num,
		"min": min_val,
		"max": max_val,
		"col": 1,
		"base": 10,
		"format": "plain",
		"rnd": "new"
	}
	async with aiohttp.ClientSession() as session:
		async with session.get(url, params=params) as response:
			if response.status == 200:
				text = await response.text()
				return [int(x) for x in text.splitlines() if x.strip()]
			return []

async def fetch_qrng_anu_integers(num: int = 1):
	"""Fetches quantum random numbers from the Australian National University QRNG API."""
	url = "https://qrng.anu.edu.au/API/jsonI.php"
	params = {"length": num, "type": "uint8"}
	async with aiohttp.ClientSession() as session:
		async with session.get(url, params=params) as response:
			if response.status == 200:
				data = await response.json()
				return data.get("data", [])
			return []

async def fetch_roll_api_result():
	"""Fetches a random dice roll from TheLastGimbus Roll-API (Physical Dice)."""
	# Base URL found in research
	base_url = "https://roll.lastgimbus.com/api"
	
	async with aiohttp.ClientSession() as session:
		try:
			# Attempt to get a simple result first
			# Research mentioned 'getRandomNumber' logic which suggests a GET might trigger it
			# or we need to check a status. 
			# Trying the most likely 'roll' endpoint or root.
			async with session.get(f"{base_url}/roll") as response:
				if response.status == 200:
					data = await response.json()
					# Expecting 'result' or 'number'
					return data.get("result", data.get("number", None))
				
				# If 202 (Accepted/Queued), we might need to wait.
				# Capturing status for debugging
				if response.status != 404:
					 print(f"Roll-API Status: {response.status}")
				
			# Fallback check on root if /roll fails
			async with session.get(base_url) as response:
				 if response.status == 200:
					 text = await response.text()
					 # If it's just a number string
					 if text.isdigit():
						 return int(text)
					 # If json
					 try:
						 data = await response.json()
						 return data.get("val", data.get("result"))
					 except:
						 pass
			
			return None
			
		except Exception as e:
			print(f"Roll-API Exception: {e}")
			return None
