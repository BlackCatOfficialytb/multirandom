import pyautogui
import time
import ctypes
import random

# Windows constants for mouse buttons
VK_LBUTTON = 0x01
VK_RBUTTON = 0x02
VK_MBUTTON = 0x04

def is_left_click_pressed():
	"""Checks if the left mouse button is currently down using Windows API."""
	return ctypes.windll.user32.GetAsyncKeyState(VK_LBUTTON) & 0x8000

def is_right_click_pressed():
	"""Checks if the right mouse button is currently down using Windows API."""
	return ctypes.windll.user32.GetAsyncKeyState(VK_RBUTTON) & 0x8000

def is_middle_click_pressed():
	"""Checks if the middle mouse button is currently down using Windows API."""
	return ctypes.windll.user32.GetAsyncKeyState(VK_MBUTTON) & 0x8000

def get_click_data(button_check_func=is_left_click_pressed):
	"""Waits for a specific click and returns (timestamp, cursor_position)."""
	# Wait for the button to be pressed
	while not button_check_func():
		time.sleep(0.005) # Tiny sleep to prevent high CPU usage
	
	t = time.perf_counter()
	pos = pyautogui.position()
	
	# Wait for the button to be released to avoid duplicate captures
	while button_check_func():
		time.sleep(0.005)
		
	return t, pos

class RealRandomUsingBetweenLeftClicks(random.Random):
	def seed(self, a=None, version=2):
		if a is None:
			t1, p1 = get_click_data(is_left_click_pressed)
			t2, p2 = get_click_data(is_left_click_pressed)
			# Use the time interval and positions to create a seed without hashing
			a = int((t2 - t1) * 10**9) + p1.x + p1.y + p2.x + p2.y
		super().seed(a, version=version)

class RealRandomUsingBetweenRightClicks(random.Random):
	def seed(self, a=None, version=2):
		if a is None:
			t1, p1 = get_click_data(is_right_click_pressed)
			t2, p2 = get_click_data(is_right_click_pressed)
			a = int((t2 - t1) * 10**9) + p1.x + p1.y + p2.x + p2.y
		super().seed(a, version=version)

class RealRandomUsingBetweenMiddleClicks(random.Random):
	def seed(self, a=None, version=2):
		if a is None:
			t1, p1 = get_click_data(is_middle_click_pressed)
			t2, p2 = get_click_data(is_middle_click_pressed)
			a = int((t2 - t1) * 10**9) + p1.x + p1.y + p2.x + p2.y
		super().seed(a, version=version)

class RealRandomUsingBetweenMixedClicks(random.Random):
	def seed(self, a=None, version=2):
		if a is None:
			# Mixed logic: Left -> Right -> Middle
			t1, p1 = get_click_data(is_left_click_pressed)
			t2, p2 = get_click_data(is_right_click_pressed)
			t3, p3 = get_click_data(is_middle_click_pressed)
			a = int((t3 - t1) * 10**9) + p1.x + p1.y + p2.x + p2.y + p3.x + p3.y
		super().seed(a, version=version)

def main():
	print("--- Click-based Randomness Test ---")
	print("Each generator requires specific mouse clicks to seed.")
	
	print("\n1. Seeding Left-Click Random (requires 2 left clicks)...")
	rl = RealRandomUsingBetweenLeftClicks()
	print(f"Result: {rl.random()}")

	print("\n2. Seeding Right-Click Random (requires 2 right clicks)...")
	rr = RealRandomUsingBetweenRightClicks()
	print(f"Result: {rr.random()}")

	print("\n3. Seeding Mixed-Click Random (requires Left -> Right -> Middle)...")
	rm = RealRandomUsingBetweenMixedClicks()
	print(f"Result: {rm.random()}")

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("\nStopped by user.")