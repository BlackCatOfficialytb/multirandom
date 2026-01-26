import aiohttp
import asyncio
import random
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple

"""
A random source using Open-Meteo weather API data.
While still not fully random and can be spoofed, it's much more reliable than any others cuz it uses hash random from random() too.
"""

class OpenMeteoAPI:
    """
    Entropy source using Open-Meteo weather API data.
    
    Fetches weather data from random locations and times to generate entropy
    for seeding random.Random. Only provides entropy - use RandomUsingOpenMeteoAPI
    for the full random interface.
    """
    
    BASE_URL = "https://api.open-meteo.com/v1/forecast"
    
    WEATHER_VARIABLES = [
        "temperature_2m",
        "relative_humidity_2m", 
        "precipitation",
        "surface_pressure",
        "wind_speed_10m",
        "wind_direction_10m",
        "cloud_cover"
    ]
    
    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)
        self._current_location: Optional[Tuple[float, float]] = None
    
    def set_current_location(self, latitude: float, longitude: float):
        """Set the current location for weather-based entropy."""
        self._current_location = (latitude, longitude)
    
    def _generate_random_location(self) -> Tuple[float, float]:
        """Generate a random latitude and longitude."""
        latitude = self._rng.uniform(-60, 70)
        longitude = self._rng.uniform(-180, 180)
        return (latitude, longitude)
    
    def _generate_random_time(self, days_back: int = 7) -> datetime:
        """Generate a random time within the past few days."""
        now = datetime.utcnow()
        random_hours = self._rng.randint(0, days_back * 24)
        return now - timedelta(hours=random_hours)
    
    async def _fetch_weather_data(
        self, 
        latitude: float, 
        longitude: float,
        target_time: Optional[datetime] = None
    ) -> Optional[dict]:
        """Fetch weather data from Open-Meteo API."""
        params = {
            "latitude": latitude,
            "longitude": longitude,
            "hourly": ",".join(self.WEATHER_VARIABLES),
            "timezone": "UTC"
        }
        
        if target_time:
            date_str = target_time.strftime("%Y-%m-%d")
            params["start_date"] = date_str
            params["end_date"] = date_str
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.BASE_URL, params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
            except Exception:
                return None
    
    async def _fetch_current_location(self) -> Optional[Tuple[float, float]]:
        """Fetch approximate current location using IP geolocation via geopy."""
        try:
            from geopy.geocoders import Nominatim
            
            # First get public IP location using ipinfo.io (free, no key needed)
            async with aiohttp.ClientSession() as session:
                async with session.get("https://ipinfo.io/json") as response:
                    if response.status == 200:
                        data = await response.json()
                        loc = data.get("loc", "")
                        if loc:
                            lat, lon = loc.split(",")
                            return (float(lat), float(lon))
            
            # Fallback: use geopy to geocode a random city for entropy
            geolocator = Nominatim(user_agent="multirandom_weather")
            # Pick a random major city for location entropy
            cities = ["Tokyo", "New York", "London", "Sydney", "Mumbai", "São Paulo"]
            city = self._rng.choice(cities)
            location = geolocator.geocode(city)
            if location:
                return (location.latitude, location.longitude)
            
            return None
        except Exception:
            return None
    
    def _extract_entropy(self, weather_data: dict, target_time: Optional[datetime] = None) -> bytes:
        """Extract entropy bytes from weather data."""
        entropy_values = []
        hourly = weather_data.get("hourly", {})
        
        hour_index = 0
        if target_time and "time" in hourly:
            times = hourly.get("time", [])
            target_hour = target_time.strftime("%Y-%m-%dT%H:00")
            if target_hour in times:
                hour_index = times.index(target_hour)
            else:
                hour_index = self._rng.randint(0, max(0, len(times) - 1))
        elif "time" in hourly:
            times = hourly.get("time", [])
            hour_index = self._rng.randint(0, max(0, len(times) - 1))
        
        for var in self.WEATHER_VARIABLES:
            values = hourly.get(var, [])
            if values and hour_index < len(values) and values[hour_index] is not None:
                entropy_values.append(values[hour_index])
        
        entropy_values.extend([
            weather_data.get("latitude", 0),
            weather_data.get("longitude", 0),
            weather_data.get("elevation", 0),
            datetime.utcnow().timestamp()
        ])
        
        entropy_str = "|".join(str(v) for v in entropy_values)
        return hashlib.sha256(entropy_str.encode()).digest()
    
    async def get_seed(
        self,
        use_random_location: bool = True,
        use_current_location: bool = False,
        use_random_time: bool = True,
        num_random_locations: int = 2
    ) -> int:
        """
        Get a seed value from weather entropy.
        
        Args:
            use_random_location: Fetch weather from random locations
            use_current_location: Fetch weather from current location
            use_random_time: Use random times for weather data
            num_random_locations: Number of random locations to sample
            
        Returns:
            Integer seed derived from weather data
        """
        entropy_pool = b""
        tasks = []
        
        # Random locations
        if use_random_location:
            for _ in range(num_random_locations):
                lat, lon = self._generate_random_location()
                target_time = self._generate_random_time() if use_random_time else None
                tasks.append((self._fetch_weather_data(lat, lon, target_time), target_time))
        
        # Current location
        if use_current_location:
            if self._current_location:
                lat, lon = self._current_location
            else:
                location = await self._fetch_current_location()
                if location:
                    lat, lon = location
                    self._current_location = location
                else:
                    lat, lon = 0, 0
            
            target_time = self._generate_random_time() if use_random_time else None
            tasks.append((self._fetch_weather_data(lat, lon, target_time), target_time))
        
        # Gather all weather data
        for task, target_time in tasks:
            weather_data = await task
            if weather_data:
                entropy = self._extract_entropy(weather_data, target_time)
                entropy_pool = hashlib.sha256(entropy_pool + entropy).digest()
        
        # Fallback if no data gathered
        if not entropy_pool:
            entropy_pool = hashlib.sha256(str(datetime.utcnow().timestamp()).encode()).digest()
        
        return int.from_bytes(entropy_pool, 'big')


class RandomUsingOpenMeteoAPI(random.Random):
    """
    A random.Random subclass seeded with weather entropy from Open-Meteo API.
    
    Uses weather data to generate a seed, then delegates all random generation
    to the standard Mersenne Twister (random.Random).
    """
    
    def __init__(self, auto_seed: bool = True):
        """
        Initialize the random generator.
        
        Args:
            auto_seed: If True, automatically seeds with weather entropy.
        """
        super().__init__()
        self._api = OpenMeteoAPI()
        
        if auto_seed:
            self.seed_from_weather()
    
    def _run_async(self, coro):
        """Helper to run async code synchronously."""
        try:
            asyncio.get_running_loop()
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        except RuntimeError:
            return asyncio.run(coro)
    
    def seed_from_weather(
        self,
        use_random_location: bool = True,
        use_current_location: bool = True,
        use_random_time: bool = True
    ):
        """Seed the random generator using weather entropy mixed with hash random."""
        try:
            # Get weather-based seed
            weather_seed = self._run_async(self._api.get_seed(
                use_random_location=use_random_location,
                use_current_location=use_current_location,
                use_random_time=use_random_time
            ))
            
            # Mix with original random module's entropy via SHA256
            from ..hash_rand.sha_rand import SHA256Random
            import time
            import os
            
            # Create SHA256 random seeded with os.urandom + time
            sha_seed = int.from_bytes(os.urandom(32), 'big') ^ int(time.time() * 1000000)
            sha_rng = SHA256Random(seed=sha_seed)
            sha_entropy = int.from_bytes(sha_rng.getrandbytes(32), 'big')
            
            # Also get some entropy from Python's random module
            orig_entropy = int.from_bytes(os.urandom(16), 'big')
            
            # Combine all entropy sources with XOR and hash
            combined = weather_seed ^ sha_entropy ^ orig_entropy
            final_seed = int.from_bytes(
                hashlib.sha256(combined.to_bytes(64, 'big')).digest(),
                'big'
            )
            
            super().seed(final_seed)
        except Exception:
            import time
            super().seed(int(time.time() * 1000000))
    
    def seed(self, a=None, version=2):
        """Seed the generator. If a is None, seeds from weather."""
        if a is None:
            self.seed_from_weather()
        else:
            super().seed(a, version)
    
    def reseed_from_weather(self):
        """Force a reseed from fresh weather data."""
        self.seed_from_weather()